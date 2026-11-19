//! High-level, typed access to PostgreSQL's [binary `COPY` format][format].
//!
//! A binary `COPY` payload is a header followed by rows, where each row is a field count and then
//! one length-prefixed value per column. That is the same layout used for the parameters of a
//! prepared statement, so [`Encode`] and [`Decode`] are reused as-is, with no per-type text
//! formatting.
//!
//! [format]: https://www.postgresql.org/docs/current/sql-copy.html#id-1.9.3.55.9

use std::ops::DerefMut;
use std::sync::Arc;

use sqlx_core::bytes::{Buf, Bytes, BytesMut};
use sqlx_core::column::ColumnOrigin;
use sqlx_core::from_row::FromRow;

use crate::arguments::PgArgumentBuffer;
use crate::column::PgColumn;
use crate::connection::PgConnection;
use crate::encode::Encode;
use crate::error::{BoxDynError, Error, Result};
use crate::ext::ustr::UStr;
use crate::message::{
    BackendMessageFormat, CommandComplete, CopyData, CopyDone, CopyOutResponse,
    DataRow, Query, ReadyForQuery,
};
use crate::row::PgRow;
use crate::statement::PgStatementMetadata;
use crate::types::Type;
use crate::{PgCopyIn, PgTypeInfo, PgValueFormat, Postgres};

/// The signature that opens every binary `COPY` payload.
const BINARY_SIGNATURE: &[u8; 11] = b"PGCOPY\n\xff\r\n\0";

/// A field count of `-1` marks the end of a binary `COPY` payload.
const BINARY_TRAILER: i16 = -1;

/// The number of buffered bytes at which [`PgCopyInBinary`] sends a `CopyData` message.
///
/// Buffering keeps the number of protocol messages low when copying many small rows.
const FLUSH_THRESHOLD: usize = 1 << 20;

/// Write the 19-byte header that opens a binary `COPY` payload:
///
/// * the signature `PGCOPY\n\xff\r\n\0`,
/// * the flags word, with no OIDs and no other options set,
/// * the length of the header extension area, which is always zero.
fn write_payload_header(buf: &mut Vec<u8>) {
    buf.extend_from_slice(BINARY_SIGNATURE);
    buf.extend_from_slice(&0_i32.to_be_bytes());
    buf.extend_from_slice(&0_i32.to_be_bytes());
}

/// Write a single value, including its length prefix, in binary `COPY` field format.
///
/// [`PgArgumentBuffer::encode()`] produces exactly this layout and takes care of `NULL`.
fn write_field<'q, T>(
    buf: &mut PgArgumentBuffer,
    value: &'q T,
) -> std::result::Result<(), BoxDynError>
where
    T: Encode<'q, Postgres>,
{
    buf.encode(value)
}

/// A row of values to write to a `COPY ... FROM STDIN WITH (FORMAT binary)`.
///
/// Implemented for tuples of up to 16 values that implement [`Encode`] and [`Type`] for
/// [`Postgres`], and for `[&dyn EncodableField]` slices for rows whose width is only known at
/// runtime.
///
/// ```rust,no_run
/// # async fn example(conn: &mut sqlx::PgConnection) -> sqlx::Result<()> {
/// # let mut copy = conn.copy_in_binary("COPY t (a, b) FROM STDIN").await?;
/// // A tuple: the width is checked at compile time.
/// copy.send_row(&(1_i32, "Alice")).await?;
///
/// // A slice of values: the width is checked against the statement at runtime.
/// copy.send_row(&[&1_i32 as &dyn EncodableField, &"Bob"]).await?;
/// # Ok(()) }
/// ```
pub trait CopyRow: Sync {
    /// The number of fields in this row.
    fn num_fields(&self) -> usize;

    /// Write every field of this row, in column order, to `buf`.
    ///
    /// Each field must be written with [`PgArgumentBuffer::encode()`] so that it carries its own
    /// length prefix.
    fn encode_fields(&self, buf: &mut PgArgumentBuffer) -> std::result::Result<(), BoxDynError>;
}

/// A single value in a binary `COPY` row.
///
/// Implemented for every type that implements [`Encode`] for [`Postgres`]. It exists so a row can
/// hold borrowed values of different types behind one trait object.
pub trait EncodableField: Sync {
    /// Write this value, including its length prefix, to `buf`.
    fn encode_field(&self, buf: &mut PgArgumentBuffer) -> std::result::Result<(), BoxDynError>;

    /// The type this value will be sent as.
    fn field_type_info(&self) -> PgTypeInfo;
}

impl<T> EncodableField for T
where
    T: for<'q> Encode<'q, Postgres> + Type<Postgres> + Sync,
{
    fn encode_field(&self, buf: &mut PgArgumentBuffer) -> std::result::Result<(), BoxDynError> {
        buf.encode(self)
    }

    fn field_type_info(&self) -> PgTypeInfo {
        self.produces().unwrap_or_else(T::type_info)
    }
}

impl CopyRow for [&dyn EncodableField] {
    fn num_fields(&self) -> usize {
        self.len()
    }

    fn encode_fields(&self, buf: &mut PgArgumentBuffer) -> std::result::Result<(), BoxDynError> {
        for field in self {
            field.encode_field(buf)?;
        }

        Ok(())
    }
}

impl<const N: usize> CopyRow for [&dyn EncodableField; N] {
    fn num_fields(&self) -> usize {
        N
    }

    fn encode_fields(&self, buf: &mut PgArgumentBuffer) -> std::result::Result<(), BoxDynError> {
        self.as_slice().encode_fields(buf)
    }
}

impl CopyRow for Vec<&dyn EncodableField> {
    fn num_fields(&self) -> usize {
        self.as_slice().num_fields()
    }

    fn encode_fields(&self, buf: &mut PgArgumentBuffer) -> std::result::Result<(), BoxDynError> {
        self.as_slice().encode_fields(buf)
    }
}

macro_rules! impl_copy_row_for_tuple {
    ($( ($idx:tt) -> $T:ident );+;) => {
        impl<$($T,)+> CopyRow for ($($T,)+)
        where
            $($T: for<'q> Encode<'q, Postgres> + Type<Postgres> + Sync,)+
        {
            fn num_fields(&self) -> usize {
                [$(stringify!($T),)+].len()
            }

            fn encode_fields(
                &self,
                buf: &mut PgArgumentBuffer,
            ) -> std::result::Result<(), BoxDynError> {
                $(write_field(buf, &self.$idx)?;)+

                Ok(())
            }
        }
    };
}

impl_copy_row_for_tuple!((0) -> T1;);
impl_copy_row_for_tuple!((0) -> T1; (1) -> T2;);
impl_copy_row_for_tuple!((0) -> T1; (1) -> T2; (2) -> T3;);
impl_copy_row_for_tuple!((0) -> T1; (1) -> T2; (2) -> T3; (3) -> T4;);
impl_copy_row_for_tuple!((0) -> T1; (1) -> T2; (2) -> T3; (3) -> T4; (4) -> T5;);
impl_copy_row_for_tuple!((0) -> T1; (1) -> T2; (2) -> T3; (3) -> T4; (4) -> T5; (5) -> T6;);
impl_copy_row_for_tuple!((0) -> T1; (1) -> T2; (2) -> T3; (3) -> T4; (4) -> T5; (5) -> T6; (6) -> T7;);
impl_copy_row_for_tuple!((0) -> T1; (1) -> T2; (2) -> T3; (3) -> T4; (4) -> T5; (5) -> T6; (6) -> T7; (7) -> T8;);
impl_copy_row_for_tuple!((0) -> T1; (1) -> T2; (2) -> T3; (3) -> T4; (4) -> T5; (5) -> T6; (6) -> T7; (7) -> T8; (8) -> T9;);
impl_copy_row_for_tuple!((0) -> T1; (1) -> T2; (2) -> T3; (3) -> T4; (4) -> T5; (5) -> T6; (6) -> T7; (7) -> T8; (8) -> T9; (9) -> T10;);
impl_copy_row_for_tuple!((0) -> T1; (1) -> T2; (2) -> T3; (3) -> T4; (4) -> T5; (5) -> T6; (6) -> T7; (7) -> T8; (8) -> T9; (9) -> T10; (10) -> T11;);
impl_copy_row_for_tuple!((0) -> T1; (1) -> T2; (2) -> T3; (3) -> T4; (4) -> T5; (5) -> T6; (6) -> T7; (7) -> T8; (8) -> T9; (9) -> T10; (10) -> T11; (11) -> T12;);
impl_copy_row_for_tuple!((0) -> T1; (1) -> T2; (2) -> T3; (3) -> T4; (4) -> T5; (5) -> T6; (6) -> T7; (7) -> T8; (8) -> T9; (9) -> T10; (10) -> T11; (11) -> T12; (12) -> T13;);
impl_copy_row_for_tuple!((0) -> T1; (1) -> T2; (2) -> T3; (3) -> T4; (4) -> T5; (5) -> T6; (6) -> T7; (7) -> T8; (8) -> T9; (9) -> T10; (10) -> T11; (11) -> T12; (12) -> T13; (13) -> T14;);
impl_copy_row_for_tuple!((0) -> T1; (1) -> T2; (2) -> T3; (3) -> T4; (4) -> T5; (5) -> T6; (6) -> T7; (7) -> T8; (8) -> T9; (9) -> T10; (10) -> T11; (11) -> T12; (12) -> T13; (13) -> T14; (14) -> T15;);
impl_copy_row_for_tuple!((0) -> T1; (1) -> T2; (2) -> T3; (3) -> T4; (4) -> T5; (5) -> T6; (6) -> T7; (7) -> T8; (8) -> T9; (9) -> T10; (10) -> T11; (11) -> T12; (12) -> T13; (13) -> T14; (14) -> T15; (15) -> T16;);

/// A `COPY ... FROM STDIN WITH (FORMAT binary)` in progress.
///
/// Created by [`PgConnection::copy_in_binary()`].
///
/// Rows are added with [`send_row()`][Self::send_row] and buffered until enough of them have
/// accumulated to make sending worthwhile; [`finish()`][Self::finish] sends the remainder and
/// completes the copy.
///
/// ```rust,no_run
/// # async fn example(conn: &mut sqlx::PgConnection) -> sqlx::Result<()> {
/// let mut copy = conn
///     .copy_in_binary("COPY users (id, name) FROM STDIN WITH (FORMAT binary)")
///     .await?;
///
/// copy.send_row(&(1_i32, "Alice")).await?;
/// copy.send_row(&(2_i32, "Bob")).await?;
///
/// assert_eq!(copy.finish().await?, 2);
/// # Ok(()) }
/// ```
///
/// If this value is dropped before [`finish()`][Self::finish] or [`abort()`][Self::abort] is
/// called, the underlying [`PgCopyIn`] aborts the copy on drop.
#[must_use = "connection will error on next use if `.finish()` or `.abort()` is not called"]
pub struct PgCopyInBinary<'c, C: DerefMut<Target = PgConnection>> {
    copy: PgCopyIn<C>,
    buffer: PgArgumentBuffer,
    /// The number of columns each row must have, as reported by the server.
    num_columns: usize,
    /// Set once the payload header has been written to `buffer`.
    header_written: bool,
    /// Set once the payload trailer has been written, after which no more rows may be sent.
    sealed: bool,
    /// The connection is owned by `copy`; this ties `'c` to it.
    _marker: std::marker::PhantomData<&'c ()>,
}

impl<'c, C: DerefMut<Target = PgConnection>> PgCopyInBinary<'c, C> {
    /// Begin a binary `COPY ... FROM STDIN` statement.
    ///
    /// Returns [`Error::InvalidArgument`] if the server is not expecting binary data, which is
    /// the case for a statement that does not say `FORMAT binary`. The copy is aborted before
    /// the error is returned, so the connection stays usable.
    pub async fn begin(conn: C, statement: &str) -> Result<Self> {
        let copy = PgCopyIn::begin(conn, statement).await?;

        if copy.is_textual() {
            let num_columns = copy.num_columns();

            copy.abort(
                "PgCopyInBinary: the statement is not using `FORMAT binary`; \
                 binary data would not be parsed correctly",
            )
            .await?;

            return Err(Error::InvalidArgument(format!(
                "the COPY statement is not using the binary format \
                 ({num_columns} column(s) of textual format); \
                 add `WITH (FORMAT binary)` to the statement"
            )));
        }

        let num_columns = copy.num_columns();

        let mut buffer = PgArgumentBuffer::default();
        buffer.reserve(BINARY_SIGNATURE.len() + 8);

        Ok(Self {
            copy,
            buffer,
            num_columns,
            header_written: false,
            sealed: false,
            _marker: std::marker::PhantomData,
        })
    }

    /// The number of columns expected in each row.
    pub fn num_columns(&self) -> usize {
        self.num_columns
    }

    /// Send a single row.
    ///
    /// Any [`CopyRow`] may be used, including tuples of values that implement [`Encode`] for
    /// [`Postgres`]:
    ///
    /// ```rust,no_run
    /// # async fn example(conn: &mut sqlx::PgConnection) -> sqlx::Result<()> {
    /// # let mut copy = conn.copy_in_binary("COPY t FROM STDIN").await?;
    /// copy.send_row(&(1_i32, "Alice", None::<i32>)).await?;
    /// # Ok(()) }
    /// ```
    ///
    /// The number of fields must match [`num_columns()`][Self::num_columns]; a mismatch is
    /// reported as [`Error::InvalidArgument`] without sending anything to the server.
    ///
    /// Rows are buffered and sent in batches, so a successful call does not mean the server has
    /// received the row yet.
    pub async fn send_row(&mut self, row: &(impl CopyRow + ?Sized)) -> Result<&mut Self> {
        if self.sealed {
            return Err(Error::InvalidArgument(
                "cannot send a row after `finish()` has been called".into(),
            ));
        }

        let num_fields = row.num_fields();

        if num_fields != self.num_columns {
            return Err(Error::InvalidArgument(format!(
                "binary COPY row has {num_fields} field(s), but the statement expects {}",
                self.num_columns
            )));
        }

        let num_fields = i16::try_from(num_fields).map_err(|_| {
            Error::InvalidArgument(format!(
                "binary COPY row has too many fields for the protocol: {num_fields} > {}",
                i16::MAX
            ))
        })?;

        let buffer_len = self.buffer.len();

        let outcome = (|| -> Result<()> {
            if !self.header_written {
                write_payload_header(&mut self.buffer);
                self.header_written = true;
            }

            self.buffer.extend_from_slice(&num_fields.to_be_bytes());

            row.encode_fields(&mut self.buffer).map_err(|source| {
                Error::Encode(format!("failed to encode row for binary COPY: {source}").into())
            })
        })();

        if let Err(error) = outcome {
            // Don't leave a partially-written row in the buffer.
            self.buffer.truncate(buffer_len);

            return Err(error);
        }

        if self.buffer.len() >= FLUSH_THRESHOLD {
            self.flush().await?;
        }

        Ok(self)
    }

    /// Send any buffered rows to the server without ending the copy.
    pub async fn flush(&mut self) -> Result<&mut Self> {
        if self.buffer.is_empty() {
            return Ok(self);
        }

        // `PgCopyIn::send()` takes `impl Deref<Target = [u8]>` and splits the data across
        // `CopyData` messages as needed.
        self.copy.send(&self.buffer[..]).await?;
        self.buffer.clear();

        Ok(self)
    }

    /// Complete the copy and return the number of rows the server reports as inserted.
    pub async fn finish(mut self) -> Result<u64> {
        if !self.header_written {
            // An empty copy is still a valid payload: header, then trailer.
            write_payload_header(&mut self.buffer);
            self.header_written = true;
        }

        self.buffer
            .extend_from_slice(&BINARY_TRAILER.to_be_bytes());
        self.sealed = true;

        self.flush().await?;

        self.copy.finish().await
    }

    /// Abort the copy, discarding any rows that were already sent.
    ///
    /// `message` is recorded in the database logs as the reason for the abort.
    pub async fn abort(mut self, message: impl Into<String>) -> Result<()> {
        self.buffer.clear();

        self.copy.abort(message).await
    }
}


/// A `COPY ... TO STDOUT WITH (FORMAT binary)` in progress.
///
/// Created by [`PgConnection::copy_out_binary()`].
///
/// Rows are decoded with [`next_row()`][Self::next_row], which returns `None` once the copy is
/// exhausted. The connection is only returned to a usable state once the stream has been read to
/// completion, so either keep reading until `None` or call [`finish()`][Self::finish] to drain
/// the rest.
///
/// ```rust,no_run
/// # async fn example(conn: &mut sqlx::PgConnection) -> sqlx::Result<()> {
/// let mut copy = conn
///     .copy_out_binary("COPY (SELECT id, name FROM users) TO STDOUT WITH (FORMAT binary)")
///     .await?;
///
/// while let Some((id, name)) = copy.next_row::<(i32, String)>().await? {
///     println!("{id}: {name}");
/// }
/// # Ok(()) }
/// ```
#[must_use = "the copy must be read to the end or drained with `.finish()`"]
pub struct PgCopyOutBinary<'c, C: DerefMut<Target = PgConnection>> {
    conn: C,
    /// The number of columns in each row, as reported by the server.
    num_columns: usize,
    /// The column metadata, used to type-check decoded values.
    metadata: Arc<PgStatementMetadata>,
    /// A partially-read `CopyData` message.
    buffer: Bytes,
    /// Set once the 19-byte payload header has been consumed.
    header_read: bool,
    /// Set once the trailer has been read.
    finished: bool,
    /// The connection is owned by `conn`; this ties `'c` to it.
    _marker: std::marker::PhantomData<&'c ()>,
}

impl<'c, C: DerefMut<Target = PgConnection>> PgCopyOutBinary<'c, C> {
    /// Begin a binary `COPY ... TO STDOUT` statement.
    ///
    /// Returns [`Error::InvalidArgument`] if the server is not sending binary data, which is the
    /// case for a statement that does not say `FORMAT binary`. The copy is drained before the
    /// error is returned, so the connection stays usable.
    pub async fn begin(conn: C, statement: &str) -> Result<Self> {
        let mut conn = conn;

        conn.wait_until_ready().await?;
        conn.inner.stream.send(Query(statement)).await?;

        let response = conn.inner.stream.recv_expect::<CopyOutResponse>().await?;
        let response = response.0;

        let num_columns = response.num_columns.unsigned_abs() as usize;

        if response.format == 0 {
            let mut this = Self {
                conn,
                num_columns,
                metadata: Arc::new(PgStatementMetadata::default()),
                buffer: Bytes::new(),
                header_read: false,
                finished: false,
                _marker: std::marker::PhantomData,
            };

            // Drain the copy so the connection isn't left mid-exchange.
            this.drain().await?;

            return Err(Error::InvalidArgument(
                "the COPY statement is not using the binary format; \
                 add `WITH (FORMAT binary)` to the statement"
                    .into(),
            ));
        }

        let metadata = PgStatementMetadata {
            columns: (0..num_columns)
                .map(|ordinal| PgColumn {
                    ordinal,
                    name: UStr::new(&format!("column{ordinal}")),
                    type_info: PgTypeInfo::UNKNOWN,
                    origin: ColumnOrigin::Unknown,
                    relation_id: None,
                    relation_attribute_no: None,
                })
                .collect(),
            column_names: Default::default(),
            parameters: Vec::new(),
        };

        Ok(Self {
            conn,
            num_columns,
            metadata: Arc::new(metadata),
            buffer: Bytes::new(),
            header_read: false,
            finished: false,
            _marker: std::marker::PhantomData,
        })
    }

    /// The number of columns in each row.
    pub fn num_columns(&self) -> usize {
        self.num_columns
    }

    /// Read the next row, decoding it into `T`.
    ///
    /// Returns `Ok(None)` once the copy is exhausted. `T` may be a tuple of values that implement
    /// [`Decode`] for [`Postgres`], or any type implementing [`FromRow`].
    ///
    /// # Errors
    ///
    /// Returns an error if the row cannot be decoded as `T`, or if the connection reports an
    /// error. Any remaining data is drained before an error is returned.
    pub async fn next_row<T>(&mut self) -> Result<Option<T>>
    where
        T: for<'r> FromRow<'r, PgRow>,
    {
        let Some(row) = self.next_pg_row().await? else {
            return Ok(None);
        };

        T::from_row(&row)
            .map(Some)
            .map_err(|source| Error::Decode(Box::new(source)))
    }

    /// Read the next row as a [`PgRow`], which can be indexed by column position.
    ///
    /// Returns `Ok(None)` once the copy is exhausted.
    pub async fn next_pg_row(&mut self) -> Result<Option<PgRow>> {
        if self.finished {
            return Ok(None);
        }

        loop {
            match self.try_take_row()? {
                RowStep::NeedMoreData => self.fill_buffer().await?,
                RowStep::Trailer => {
                    self.finished = true;
                    self.drain_tail().await?;

                    return Ok(None);
                }
                RowStep::Row(data) => {
                    return Ok(Some(PgRow {
                        data,
                        format: PgValueFormat::Binary,
                        metadata: self.metadata.clone(),
                    }))
                }
            }
        }
    }

    /// Read all remaining rows, decoding each into `T`.
    pub async fn read_all<T>(mut self) -> Result<Vec<T>>
    where
        T: for<'r> FromRow<'r, PgRow>,
    {
        let mut rows = Vec::new();

        while let Some(row) = self.next_row::<T>().await? {
            rows.push(row);
        }

        Ok(rows)
    }

    /// Discard the remaining rows so the connection can be used again.
    pub async fn finish(mut self) -> Result<()> {
        if !self.finished {
            self.drain().await?;
        }

        Ok(())
    }
}

/// The result of trying to read one row out of the buffered `CopyData` bytes.
enum RowStep {
    /// Not enough data buffered yet; read another `CopyData` message.
    NeedMoreData,
    /// The trailer was read; the copy is over.
    Trailer,
    /// A complete row.
    Row(DataRow),
}

impl<C: DerefMut<Target = PgConnection>> PgCopyOutBinary<'_, C> {
    /// Try to read one row out of `self.buffer`, consuming it on success.
    fn try_take_row(&mut self) -> Result<RowStep> {
        if !self.header_read {
            let Some(consumed) = parse_payload_header(&self.buffer)? else {
                return Ok(RowStep::NeedMoreData);
            };

            self.buffer.advance(consumed);
            self.header_read = true;
        }

        let Some((step, consumed)) = parse_row(&self.buffer, self.num_columns)? else {
            return Ok(RowStep::NeedMoreData);
        };

        self.buffer.advance(consumed);

        Ok(step)
    }

    /// Read the next `CopyData` message into `self.buffer`, or finish the copy if it's over.
    async fn fill_buffer(&mut self) -> Result<()> {
        match self.conn.inner.stream.recv().await {
            Ok(message) => match message.format {
                BackendMessageFormat::CopyData => {
                    let data = message.decode::<CopyData<Bytes>>()?.0;

                    if self.buffer.is_empty() {
                        self.buffer = data;
                    } else {
                        let mut joined =
                            BytesMut::with_capacity(self.buffer.len() + data.len());
                        joined.extend_from_slice(&self.buffer);
                        joined.extend_from_slice(&data);
                        self.buffer = joined.freeze();
                    }

                    Ok(())
                }
                BackendMessageFormat::CopyDone => {
                    let _ = message.decode::<CopyDone>()?;
                    self.drain_tail().await
                }
                format => Err(err_protocol!(
                    "unexpected message during COPY TO STDOUT: {format:?}"
                )),
            },
            Err(error) => {
                // An error from the server ends the copy; make sure the connection is left in a
                // usable state before reporting it.
                let _ = self.drain_tail().await;

                Err(error)
            }
        }
    }

    /// Read and discard everything up to `ReadyForQuery`.
    async fn drain_tail(&mut self) -> Result<()> {
        self.buffer.clear();

        loop {
            match self.conn.inner.stream.recv().await {
                Ok(message) => match message.format {
                    BackendMessageFormat::CopyData | BackendMessageFormat::CopyDone => continue,
                    BackendMessageFormat::CommandComplete => {
                        let _ = message.decode::<CommandComplete>()?;
                        continue;
                    }
                    BackendMessageFormat::ReadyForQuery => {
                        let _ = message.decode::<ReadyForQuery>()?;
                        self.finished = true;

                        return Ok(());
                    }
                    format => {
                        return Err(err_protocol!(
                            "unexpected message while draining COPY TO STDOUT: {format:?}"
                        ))
                    }
                },
                Err(error) => return Err(error),
            }
        }
    }

    /// Read and discard all remaining rows.
    async fn drain(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }

        self.buffer.clear();

        self.drain_tail().await
    }
}

/// Parse one row out of `buf`.
///
/// Returns `Ok(None)` if `buf` does not yet hold a complete row. Otherwise returns the row and the
/// number of bytes it occupied.
fn parse_row(buf: &[u8], num_columns: usize) -> Result<Option<(RowStep, usize)>> {
    let mut cursor = buf;

    if cursor.len() < 2 {
        return Ok(None);
    }

    let field_count = i16::from_be_bytes([cursor[0], cursor[1]]);
    cursor = &cursor[2..];

    if field_count == BINARY_TRAILER {
        return Ok(Some((RowStep::Trailer, 2)));
    }

    let field_count = usize::try_from(field_count)
        .map_err(|_| err_protocol!("negative field count in binary COPY row: {field_count}"))?;

    if field_count != num_columns {
        return Err(err_protocol!(
            "binary COPY row has {field_count} field(s), but the statement has {num_columns} column(s)"
        ));
    }

    // The binary COPY row layout is identical to `DataRow` except for its field count, which is
    // an `i16` here and a `u16` there, so copy the fields into a `DataRow` buffer as we go.
    let mut storage = Vec::with_capacity(cursor.len() + 2);
    storage.extend_from_slice(&(field_count as u16).to_be_bytes());

    let mut values = Vec::with_capacity(field_count);
    let mut consumed = 2;

    for _ in 0..field_count {
        if cursor.len() < 4 {
            return Ok(None);
        }

        let len = i32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);

        storage.extend_from_slice(&cursor[..4]);
        cursor = &cursor[4..];
        consumed += 4;

        if len == -1 {
            values.push(None);
            continue;
        }

        let len = usize::try_from(len)
            .map_err(|_| err_protocol!("negative field length in binary COPY row: {len}"))?;

        if cursor.len() < len {
            return Ok(None);
        }

        let value_start = storage.len() as u32;

        storage.extend_from_slice(&cursor[..len]);
        cursor = &cursor[len..];
        consumed += len;

        values.push(Some(value_start..(storage.len() as u32)));
    }

    Ok(Some((
        RowStep::Row(DataRow {
            storage: Bytes::from(storage),
            values,
        }),
        consumed,
    )))
}

impl PgConnection {
    /// Issue a `COPY ... FROM STDIN WITH (FORMAT binary)` statement and begin sending rows in
    /// Postgres' binary `COPY` format.
    ///
    /// This is a higher-level alternative to [`copy_in_raw()`][Self::copy_in_raw]: values are
    /// encoded with their [`Encode`] implementations, exactly as they would be for a bind
    /// parameter, and rows are buffered so that many small rows do not each cost a round trip.
    ///
    /// The statement must specify `FORMAT binary`; otherwise [`Error::InvalidArgument`] is
    /// returned and the copy is aborted, leaving the connection usable.
    ///
    /// ```rust,no_run
    /// # async fn example(conn: &mut sqlx::PgConnection) -> sqlx::Result<()> {
    /// let mut copy = conn
    ///     .copy_in_binary("COPY users (id, name) FROM STDIN WITH (FORMAT binary)")
    ///     .await?;
    ///
    /// copy.send_row(&(1_i32, "Alice")).await?;
    /// copy.send_row(&(2_i32, "Bob")).await?;
    ///
    /// assert_eq!(copy.finish().await?, 2);
    /// # Ok(()) }
    /// ```
    ///
    /// ### Note
    /// [`PgCopyInBinary::finish`] or [`PgCopyInBinary::abort`] must be called when finished, or
    /// the connection will return an error the next time it is used.
    pub async fn copy_in_binary(&mut self, statement: &str) -> Result<PgCopyInBinary<'_, &mut Self>> {
        PgCopyInBinary::begin(self, statement).await
    }

    /// Issue a `COPY ... TO STDOUT WITH (FORMAT binary)` statement and begin reading rows in
    /// Postgres' binary `COPY` format.
    ///
    /// This is a higher-level alternative to [`copy_out_raw()`][Self::copy_out_raw]: rows are
    /// decoded with their [`Decode`] implementations, exactly as they would be from a query
    /// result, and can be read as [`PgRow`]s or any [`FromRow`] type.
    ///
    /// The statement must specify `FORMAT binary`; otherwise [`Error::InvalidArgument`] is
    /// returned after draining the copy, leaving the connection usable.
    ///
    /// ```rust,no_run
    /// # async fn example(conn: &mut sqlx::PgConnection) -> sqlx::Result<()> {
    /// let mut copy = conn
    ///     .copy_out_binary("COPY (SELECT id, name FROM users) TO STDOUT WITH (FORMAT binary)")
    ///     .await?;
    ///
    /// while let Some((id, name)) = copy.next_row::<(i32, String)>().await? {
    ///     println!("{id}: {name}");
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// ### Note
    /// As with [`copy_out_raw()`][Self::copy_out_raw], the stream must be read to completion for
    /// the connection to be immediately reusable; [`PgCopyOutBinary::finish`] drains any
    /// remaining data.
    pub async fn copy_out_binary(
        &mut self,
        statement: &str,
    ) -> Result<PgCopyOutBinary<'_, &mut Self>> {
        PgCopyOutBinary::begin(self, statement).await
    }
}

/// Parse the header that opens a binary `COPY` payload.
///
/// Returns `Ok(None)` if `buf` does not yet hold the whole header, otherwise the number of bytes
/// it occupied.
fn parse_payload_header(buf: &[u8]) -> Result<Option<usize>> {
    if buf.len() < 19 {
        return Ok(None);
    }

    if &buf[..11] != BINARY_SIGNATURE {
        return Err(err_protocol!(
            "not a binary COPY payload: signature mismatch (got {:?})",
            &buf[..11]
        ));
    }

    let flags = i32::from_be_bytes([buf[11], buf[12], buf[13], buf[14]]);

    // Bit 16 means the rows carry type OIDs; no other bits are defined.
    if flags & !0x0001_0000 != 0 || flags == 0x0001_0000 {
        return Err(err_protocol!(
            "unsupported binary COPY flags: {flags:#010x}"
        ));
    }

    let header_extension_len = i32::from_be_bytes([buf[15], buf[16], buf[17], buf[18]]);

    let header_extension_len = usize::try_from(header_extension_len).map_err(|_| {
        err_protocol!(
            "negative header extension length in binary COPY payload: {header_extension_len}"
        )
    })?;

    let total = 19 + header_extension_len;

    if buf.len() < total {
        return Ok(None);
    }

    Ok(Some(total))
}
