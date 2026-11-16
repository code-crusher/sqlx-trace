use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};

use bytes::{Buf, Bytes, BytesMut};

use crate::error::Error;
use crate::io::MySqlBufExt;
use crate::io::{ProtocolDecode, ProtocolEncode};
use crate::net::{BufferedSocket, Socket};
use crate::protocol::response::{EofPacket, ErrPacket, OkPacket, Status};
use crate::protocol::statement::{PrepareOk, StmtClose};
use crate::protocol::text::ColumnDefinition;
use crate::protocol::{Capabilities, Packet};
use crate::{MySqlConnectOptions, MySqlDatabaseError};

/// The maximum total payload that we accept for a single (possibly reassembled)
/// packet: 1 GiB, MySQL's own hard maximum for `max_allowed_packet`.
///
/// Without this cap, a hostile server could stream an unbounded number of
/// 16 MiB packet parts and exhaust the client's memory.
const MAX_PACKET_PAYLOAD_LEN: usize = 1024 * 1024 * 1024;

pub struct MySqlStream<S = Box<dyn Socket>> {
    // Wrapping the socket in `Box` allows us to unsize in-place.
    pub(crate) socket: BufferedSocket<S>,
    pub(crate) server_version: (u16, u16, u16),
    pub(super) capabilities: Capabilities,
    pub(crate) sequence_id: u8,
    pub(crate) waiting: VecDeque<Waiting>,
    pub(crate) is_tls: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Waiting {
    // waiting for a result set
    Result,

    // waiting for a row within a result set
    Row,

    // waiting for the response to COM_STMT_PREPARE: the COM_STMT_PREPARE_OK packet,
    // the parameter definitions, an optional EOF packet, the column definitions and
    // another optional EOF packet.
    //
    // The response is tracked so that a future that is dropped partway through
    // reading it (e.g. by cancellation) leaves enough state behind for the next
    // `wait_until_ready` to resume reading it. Without this, the leftover packets
    // are decoded as the response to the *next* command issued on the connection.
    Prepare(PrepareState),
}

/// How much of a `COM_STMT_PREPARE` response has been read so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreparePhase {
    /// waiting for the COM_STMT_PREPARE_OK packet
    Ok,
    /// waiting for this many parameter definition packets; `columns` is the
    /// number of column definitions to expect afterwards
    Params { left: u16, columns: u16 },
    /// waiting for the EOF packet terminating the parameter definitions
    ParamsEof { columns: u16 },
    /// waiting for this many column definition packets
    Columns { left: u16 },
    /// waiting for the EOF packet terminating the column definitions
    ColumnsEof,
    /// the complete response has been read
    Done,
}

/// Tracks the progress of an in-flight `COM_STMT_PREPARE` response so it can be
/// resumed (or drained) if the future reading it is dropped partway through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrepareState {
    /// the statement id the server assigned, once COM_STMT_PREPARE_OK was read
    pub id: Option<u32>,
    pub phase: PreparePhase,
}

impl PrepareState {
    pub(crate) fn new() -> Self {
        Self {
            id: None,
            phase: PreparePhase::Ok,
        }
    }
}

impl Default for PrepareState {
    fn default() -> Self {
        Self::new()
    }
}

/// Progress through a `COM_STMT_PREPARE` response, reported one packet at a time
/// by [`MySqlStream::recv_prepare_step`].
#[derive(Debug)]
pub(crate) enum PrepareStep {
    /// the COM_STMT_PREPARE_OK packet was read
    Ok { statement_id: u32, params: u16 },

    /// a parameter definition was read
    Parameter,

    /// a result-set column definition was read
    Column(ColumnDefinition),

    /// one of the EOF packets terminating a definition list was read
    Eof,

    /// the whole response has been read and the tracking entry was removed from
    /// `waiting`; carries the statement id if one was assigned
    Done(Option<u32>),
}

impl<S: Socket> MySqlStream<S> {
    pub(crate) fn with_socket(options: &MySqlConnectOptions, socket: S) -> Self {
        let mut capabilities = Capabilities::PROTOCOL_41
            | Capabilities::IGNORE_SPACE
            | Capabilities::DEPRECATE_EOF
            | Capabilities::TRANSACTIONS
            | Capabilities::SECURE_CONNECTION
            | Capabilities::PLUGIN_AUTH_LENENC_DATA
            | Capabilities::MULTI_STATEMENTS
            | Capabilities::MULTI_RESULTS
            | Capabilities::PLUGIN_AUTH
            | Capabilities::PS_MULTI_RESULTS
            | Capabilities::SSL;

        if options.database.is_some() {
            capabilities |= Capabilities::CONNECT_WITH_DB;
        }

        if options.found_rows {
            capabilities |= Capabilities::FOUND_ROWS;
        }

        Self {
            waiting: VecDeque::new(),
            capabilities,
            server_version: (0, 0, 0),
            sequence_id: 0,
            socket: BufferedSocket::new(socket),
            is_tls: false,
        }
    }

    pub(crate) async fn wait_until_ready(&mut self) -> Result<(), Error> {
        if !self.socket.write_buffer().is_empty() {
            self.socket.flush().await?;
        }

        loop {
            // figure out what's at the front without holding the borrow
            // into `self.waiting` across the arms that take `&mut self`
            let front = match self.waiting.front() {
                Some(Waiting::Prepare(_)) => 0,
                Some(Waiting::Row) => 1,
                Some(Waiting::Result) => 2,
                None => break,
            };

            match front {
                0 => {
                    // Read and discard the remaining packets of a prepare response
                    // that nobody consumed (the prepare was cancelled or failed and
                    // the caller gave up on it). The prepared statement, if any, is
                    // then closed so it doesn't leak on the server.
                    let statement_id = loop {
                        match self.recv_prepare_step().await? {
                            PrepareStep::Done(id) => break id,
                            // ignore the contents of the response; we only care
                            // about consuming exactly the packets that belong to it
                            PrepareStep::Ok { .. }
                            | PrepareStep::Parameter
                            | PrepareStep::Column(_)
                            | PrepareStep::Eof => {}
                        }
                    };

                    // COM_STMT_CLOSE has no response
                    if let Some(statement_id) = statement_id {
                        self.send_packet(StmtClose {
                            statement: statement_id,
                        })
                        .await?;
                    }
                }

                1 => {
                    let packet = self.recv_packet().await?;

                    if !packet.is_empty() && packet[0] == 0xfe && packet.len() < 9 {
                        let eof = packet.eof(self.capabilities)?;

                        if eof.status.contains(Status::SERVER_MORE_RESULTS_EXISTS) {
                            *self.waiting.front_mut().unwrap() = Waiting::Result;
                        } else {
                            self.waiting.pop_front();
                        };
                    }
                }

                _ => {
                    let packet = self.recv_packet().await?;

                    if !packet.is_empty() && (packet[0] == 0x00 || packet[0] == 0xff) {
                        let ok = packet.ok()?;

                        if !ok.status.contains(Status::SERVER_MORE_RESULTS_EXISTS) {
                            self.waiting.pop_front();
                        }
                    } else {
                        *self.waiting.front_mut().unwrap() = Waiting::Row;
                        self.skip_result_metadata(packet).await?;
                    }
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn send_packet<'en, T>(&mut self, payload: T) -> Result<(), Error>
    where
        T: ProtocolEncode<'en, Capabilities>,
    {
        self.sequence_id = 0;
        self.write_packet(payload)?;
        self.flush().await?;
        Ok(())
    }

    pub(crate) fn write_packet<'en, T>(&mut self, payload: T) -> Result<(), Error>
    where
        T: ProtocolEncode<'en, Capabilities>,
    {
        self.socket
            .write_with(Packet(payload), (self.capabilities, &mut self.sequence_id))
    }

    async fn recv_packet_part(&mut self) -> Result<Bytes, Error> {
        // https://dev.mysql.com/doc/dev/mysql-server/8.0.12/page_protocol_basic_packets.html
        // https://mariadb.com/kb/en/library/0-packet/#standard-packet

        let mut header: Bytes = self.socket.read(4).await?;

        // cannot overflow
        #[allow(clippy::cast_possible_truncation)]
        let packet_size = header.get_uint_le(3) as usize;
        let sequence_id = header.get_u8();

        self.sequence_id = sequence_id.wrapping_add(1);

        let payload: Bytes = self.socket.read(packet_size).await?;

        // TODO: packet compression

        Ok(payload)
    }

    // receive the next packet from the database server
    // may block (async) on more data from the server
    pub(crate) async fn recv_packet(&mut self) -> Result<Packet<Bytes>, Error> {
        let payload = self.recv_packet_part().await?;
        let payload = if payload.len() < 0xFF_FF_FF {
            payload
        } else {
            let mut final_payload = BytesMut::with_capacity(0xFF_FF_FF * 2);
            final_payload.extend_from_slice(&payload);

            drop(payload); // we don't need the allocation anymore

            let mut last_read = 0xFF_FF_FF;
            while last_read == 0xFF_FF_FF {
                let part = self.recv_packet_part().await?;
                last_read = part.len();

                if final_payload.len() + part.len() > MAX_PACKET_PAYLOAD_LEN {
                    return Err(err_protocol!(
                        "reassembled packet payload of {} bytes exceeds maximum packet payload of {MAX_PACKET_PAYLOAD_LEN} bytes",
                        final_payload.len() + part.len()
                    ));
                }

                final_payload.extend_from_slice(&part);
            }
            final_payload.into()
        };

        if payload
            .first()
            .ok_or(err_protocol!("Packet empty"))?
            .eq(&0xff)
        {
            self.waiting.pop_front();

            // instead of letting this packet be looked at everywhere, we check here
            // and emit a proper Error
            return Err(
                MySqlDatabaseError(ErrPacket::decode_with(payload, self.capabilities)?).into(),
            );
        }

        Ok(Packet(payload))
    }

    pub(crate) async fn recv<'de, T>(&mut self) -> Result<T, Error>
    where
        T: ProtocolDecode<'de, Capabilities>,
    {
        self.recv_packet().await?.decode_with(self.capabilities)
    }

    pub(crate) async fn recv_ok(&mut self) -> Result<OkPacket, Error> {
        self.recv_packet().await?.ok()
    }

    pub(crate) async fn maybe_recv_eof(&mut self) -> Result<Option<EofPacket>, Error> {
        if self.capabilities.contains(Capabilities::DEPRECATE_EOF) {
            Ok(None)
        } else {
            self.recv().await.map(Some)
        }
    }

    /// Read one packet of the tracked `COM_STMT_PREPARE` response and advance the
    /// state recorded in the `Waiting::Prepare` entry at the front of `waiting`.
    ///
    /// Exactly one packet is consumed per call, and the entry is updated *after*
    /// the packet has been fully read. If the calling future is dropped between
    /// packets the next call resumes at exactly the right place.
    ///
    /// If anything fails the entry is removed from `waiting`; the connection is
    /// out of sync at that point so tracking it any further is pointless.
    pub(crate) async fn recv_prepare_step(&mut self) -> Result<PrepareStep, Error> {
        match self.recv_prepare_step_inner().await {
            Ok(step) => Ok(step),
            Err(error) => {
                if matches!(self.waiting.front(), Some(Waiting::Prepare(_))) {
                    self.waiting.pop_front();
                }

                Err(error)
            }
        }
    }

    async fn recv_prepare_step_inner(&mut self) -> Result<PrepareStep, Error> {
        let phase = match self.waiting.front() {
            Some(Waiting::Prepare(state)) => state.phase,
            _ => {
                return Err(err_protocol!(
                    "recv_prepare_step called without a pending prepare response"
                ));
            }
        };

        let deprecate_eof = self.capabilities.contains(Capabilities::DEPRECATE_EOF);

        match phase {
            PreparePhase::Ok => {
                let packet = self.recv_packet().await?;

                if packet[0] != 0x00 {
                    return Err(err_protocol!(
                        "expected 0x00 (COM_STMT_PREPARE_OK) but found 0x{:02x}",
                        packet[0]
                    ));
                }

                let ok: PrepareOk = packet.decode_with(self.capabilities)?;

                if ok.params > 4096 || ok.columns > 4096 {
                    return Err(err_protocol!(
                        "COM_STMT_PREPARE_OK claims {} parameters and {} columns but the maximum supported is 4096",
                        ok.params,
                        ok.columns
                    ));
                }

                let phase = if ok.params > 0 {
                    PreparePhase::Params {
                        left: ok.params,
                        columns: ok.columns,
                    }
                } else {
                    Self::phase_after_parameters(ok.columns)
                };

                self.set_prepare_state(|state| {
                    state.id = Some(ok.statement_id);
                    state.phase = phase;
                });

                Ok(PrepareStep::Ok {
                    statement_id: ok.statement_id,
                    params: ok.params,
                })
            }

            PreparePhase::Params { left, columns } => {
                let _: ColumnDefinition = self.recv().await?;
                let left = left - 1;

                if left > 0 {
                    self.set_prepare_phase(PreparePhase::Params { left, columns });
                } else if deprecate_eof {
                    self.set_prepare_phase(Self::phase_after_parameters(columns));
                } else {
                    self.set_prepare_phase(PreparePhase::ParamsEof { columns });
                }

                Ok(PrepareStep::Parameter)
            }

            PreparePhase::ParamsEof { columns } => {
                let _ = self.recv_eof().await?;

                self.set_prepare_phase(Self::phase_after_parameters(columns));

                Ok(PrepareStep::Eof)
            }

            PreparePhase::Columns { left } => {
                let def: ColumnDefinition = self.recv().await?;
                let left = left - 1;

                if left > 0 {
                    self.set_prepare_phase(PreparePhase::Columns { left });
                } else if deprecate_eof {
                    self.set_prepare_phase(PreparePhase::Done);
                } else {
                    self.set_prepare_phase(PreparePhase::ColumnsEof);
                }

                Ok(PrepareStep::Column(def))
            }

            PreparePhase::ColumnsEof => {
                let _ = self.recv_eof().await?;

                self.set_prepare_phase(PreparePhase::Done);

                Ok(PrepareStep::Eof)
            }

            PreparePhase::Done => match self.waiting.pop_front() {
                Some(Waiting::Prepare(state)) => Ok(PrepareStep::Done(state.id)),
                other => {
                    if let Some(front) = other {
                        self.waiting.push_front(front);
                    }

                    Err(err_protocol!(
                        "prepare response consumed but the tracking entry was missing"
                    ))
                }
            },
        }
    }

    fn phase_after_parameters(columns: u16) -> PreparePhase {
        if columns > 0 {
            PreparePhase::Columns { left: columns }
        } else {
            PreparePhase::Done
        }
    }

    async fn recv_eof(&mut self) -> Result<EofPacket, Error> {
        let packet = self.recv_packet().await?;

        packet.eof(self.capabilities)
    }

    fn set_prepare_phase(&mut self, phase: PreparePhase) {
        if let Some(Waiting::Prepare(state)) = self.waiting.front_mut() {
            state.phase = phase;
        }
    }

    fn set_prepare_state(&mut self, f: impl FnOnce(&mut PrepareState)) {
        if let Some(Waiting::Prepare(state)) = self.waiting.front_mut() {
            f(state);
        }
    }

    async fn skip_result_metadata(&mut self, mut packet: Packet<Bytes>) -> Result<(), Error> {
        let num_columns: u64 = packet.get_uint_lenenc()?; // column count

        // the server advertised a column count larger than we support; reading
        // that many packets would consume packets belonging to the next response
        if num_columns > 4096 {
            return Err(err_protocol!(
                "result-set metadata claims {num_columns} columns but the maximum supported is 4096"
            ));
        }

        for _ in 0..num_columns {
            let _ = self.recv_packet().await?;
        }

        self.maybe_recv_eof().await?;

        Ok(())
    }

    pub fn boxed_socket(self) -> MySqlStream {
        MySqlStream {
            socket: self.socket.boxed(),
            server_version: self.server_version,
            capabilities: self.capabilities,
            sequence_id: self.sequence_id,
            waiting: self.waiting,
            is_tls: self.is_tls,
        }
    }
}

impl<S> Deref for MySqlStream<S> {
    type Target = BufferedSocket<S>;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl<S> DerefMut for MySqlStream<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}
