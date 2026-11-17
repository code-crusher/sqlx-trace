use std::fmt::{self, Debug, Display, Formatter};
use std::ops::{Bound, Range, RangeBounds, RangeFrom, RangeInclusive, RangeTo, RangeToInclusive};

use bitflags::bitflags;
use sqlx_core::bytes::Buf;

use crate::decode::Decode;
use crate::encode::{Encode, IsNull};
use crate::error::BoxDynError;
use crate::type_info::{PgType, PgTypeKind};
use crate::types::Type;
use crate::{PgArgumentBuffer, PgHasArrayType, PgTypeInfo, PgValueFormat, PgValueRef, Postgres};

// https://github.com/postgres/postgres/blob/2f48ede080f42b97b594fb14102c82ca1001b80c/src/include/utils/rangetypes.h#L35-L44
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct RangeFlags: u8 {
        const EMPTY = 0x01;
        const LB_INC = 0x02;
        const UB_INC = 0x04;
        const LB_INF = 0x08;
        const UB_INF = 0x10;
        const LB_NULL = 0x20; // not used
        const UB_NULL = 0x40; // not used
        const CONTAIN_EMPTY = 0x80; // internal
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PgRange<T> {
    pub start: Bound<T>,
    pub end: Bound<T>,
}

/// Provides information necessary to encode and decode Postgres ranges as compatible Rust types.
///
/// This is the analogue of [`PgHasArrayType`][crate::PgHasArrayType] for range types.
/// Implementing this trait for some type `T` enables the `Type`, `Encode` and `Decode` impls
/// for `PgRange<T>`, as well as the `PgHasArrayType` impl for `PgRange<T>`.
///
/// It is implemented for the element types of the built-in range types:
/// `i32` (`int4range`), `i64` (`int8range`), `BigDecimal`/`Decimal` (`numrange`),
/// `NaiveDate`/`time::Date` (`daterange`), `NaiveDateTime`/`time::PrimitiveDateTime` (`tsrange`)
/// and `DateTime<Tz>`/`time::OffsetDateTime` (`tstzrange`).
///
/// Additionally, this trait may be implemented for your own types to use `PgRange`
/// with a user-defined range type, e.g. one created with
///
/// ```sql
/// CREATE TYPE float_range AS RANGE (subtype = float8, subtype_diff = float8mi);
/// ```
///
/// For instance, to use `PgRange<FloatRange>` where `FloatRange` is a newtype around `f64`:
///
/// ```rust,ignore
/// #[derive(Debug, Clone, Copy, PartialEq, sqlx::Type, sqlx::Encode, sqlx::Decode)]
/// #[sqlx(transparent)]
/// struct FloatRange(f64);
///
/// impl PgHasRangeType for FloatRange {
///     fn range_type_info() -> PgTypeInfo {
///         PgTypeInfo::with_name("float_range")
///     }
///
///     fn range_array_type_info() -> PgTypeInfo {
///         PgTypeInfo::array_of("float_range")
///     }
/// }
/// ```
///
/// The default implementation of `range_compatible()` requires the Postgres type to be a range
/// whose element type is compatible with `T`. Implementations that want to restrict the
/// accepted range type further may override it.
///
/// [`PgHasArrayType`]: crate::PgHasArrayType
pub trait PgHasRangeType {
    /// The range type for which `Self` is the element type.
    fn range_type_info() -> PgTypeInfo;

    /// The array type of the range returned by [`range_type_info()`](Self::range_type_info).
    fn range_array_type_info() -> PgTypeInfo;

    fn range_compatible(ty: &PgTypeInfo) -> bool
    where
        Self: Type<Postgres>,
    {
        // we require the declared type to be a _range_ with an
        // element type that is acceptable
        if let PgTypeKind::Range(element) = &ty.kind() {
            return <Self as Type<Postgres>>::compatible(element);
        }

        false
    }
}

impl<T> From<[Bound<T>; 2]> for PgRange<T> {
    fn from(v: [Bound<T>; 2]) -> Self {
        let [start, end] = v;
        Self { start, end }
    }
}

impl<T> From<(Bound<T>, Bound<T>)> for PgRange<T> {
    fn from(v: (Bound<T>, Bound<T>)) -> Self {
        Self {
            start: v.0,
            end: v.1,
        }
    }
}

impl<T> From<Range<T>> for PgRange<T> {
    fn from(v: Range<T>) -> Self {
        Self {
            start: Bound::Included(v.start),
            end: Bound::Excluded(v.end),
        }
    }
}

impl<T> From<RangeFrom<T>> for PgRange<T> {
    fn from(v: RangeFrom<T>) -> Self {
        Self {
            start: Bound::Included(v.start),
            end: Bound::Unbounded,
        }
    }
}

impl<T> From<RangeInclusive<T>> for PgRange<T> {
    fn from(v: RangeInclusive<T>) -> Self {
        let (start, end) = v.into_inner();
        Self {
            start: Bound::Included(start),
            end: Bound::Included(end),
        }
    }
}

impl<T> From<RangeTo<T>> for PgRange<T> {
    fn from(v: RangeTo<T>) -> Self {
        Self {
            start: Bound::Unbounded,
            end: Bound::Excluded(v.end),
        }
    }
}

impl<T> From<RangeToInclusive<T>> for PgRange<T> {
    fn from(v: RangeToInclusive<T>) -> Self {
        Self {
            start: Bound::Unbounded,
            end: Bound::Included(v.end),
        }
    }
}

impl<T> RangeBounds<T> for PgRange<T> {
    fn start_bound(&self) -> Bound<&T> {
        match self.start {
            Bound::Included(ref start) => Bound::Included(start),
            Bound::Excluded(ref start) => Bound::Excluded(start),
            Bound::Unbounded => Bound::Unbounded,
        }
    }

    fn end_bound(&self) -> Bound<&T> {
        match self.end {
            Bound::Included(ref end) => Bound::Included(end),
            Bound::Excluded(ref end) => Bound::Excluded(end),
            Bound::Unbounded => Bound::Unbounded,
        }
    }
}

impl<T> Type<Postgres> for PgRange<T>
where
    T: PgHasRangeType + Type<Postgres>,
{
    fn type_info() -> PgTypeInfo {
        <T as PgHasRangeType>::range_type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <T as PgHasRangeType>::range_compatible(ty)
    }
}

impl<T> PgHasArrayType for PgRange<T>
where
    T: PgHasRangeType,
{
    fn array_type_info() -> PgTypeInfo {
        <T as PgHasRangeType>::range_array_type_info()
    }
}

impl<'q, T> Encode<'q, Postgres> for PgRange<T>
where
    T: Encode<'q, Postgres>,
{
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        // https://github.com/postgres/postgres/blob/2f48ede080f42b97b594fb14102c82ca1001b80c/src/backend/utils/adt/rangetypes.c#L245

        let mut flags = RangeFlags::empty();

        flags |= match self.start {
            Bound::Included(_) => RangeFlags::LB_INC,
            Bound::Unbounded => RangeFlags::LB_INF,
            Bound::Excluded(_) => RangeFlags::empty(),
        };

        flags |= match self.end {
            Bound::Included(_) => RangeFlags::UB_INC,
            Bound::Unbounded => RangeFlags::UB_INF,
            Bound::Excluded(_) => RangeFlags::empty(),
        };

        buf.push(flags.bits());

        if let Bound::Included(v) | Bound::Excluded(v) = &self.start {
            buf.encode(v)?;
        }

        if let Bound::Included(v) | Bound::Excluded(v) = &self.end {
            buf.encode(v)?;
        }

        // ranges are themselves never null
        Ok(IsNull::No)
    }
}

impl<'r, T> Decode<'r, Postgres> for PgRange<T>
where
    T: Type<Postgres> + for<'a> Decode<'a, Postgres>,
{
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        match value.format {
            PgValueFormat::Binary => {
                // If the range type is a custom type that has not been resolved yet
                // (e.g. in the simple query protocol) the kind will panic, so fall back
                // to the element type of `T` instead.
                let element_info;
                let element_ty = if matches!(value.type_info.0, PgType::Custom(_)) {
                    element_info = <T as Type<Postgres>>::type_info();
                    &element_info
                } else {
                    match value.type_info.0.kind() {
                        PgTypeKind::Range(element) => element,
                        _ => {
                            return Err(format!("unexpected non-range type {}", value.type_info)
                                .into());
                        }
                    }
                };

                let mut buf = value.as_bytes()?;

                let mut start = Bound::Unbounded;
                let mut end = Bound::Unbounded;

                let flags = RangeFlags::from_bits_truncate(buf.get_u8());

                if flags.contains(RangeFlags::EMPTY) {
                    return Ok(PgRange { start, end });
                }

                if !flags.contains(RangeFlags::LB_INF) {
                    let value =
                        T::decode(PgValueRef::get(&mut buf, value.format, element_ty.clone())?)?;

                    start = if flags.contains(RangeFlags::LB_INC) {
                        Bound::Included(value)
                    } else {
                        Bound::Excluded(value)
                    };
                }

                if !flags.contains(RangeFlags::UB_INF) {
                    let value =
                        T::decode(PgValueRef::get(&mut buf, value.format, element_ty.clone())?)?;

                    end = if flags.contains(RangeFlags::UB_INC) {
                        Bound::Included(value)
                    } else {
                        Bound::Excluded(value)
                    };
                }

                Ok(PgRange { start, end })
            }

            PgValueFormat::Text => {
                // https://github.com/postgres/postgres/blob/2f48ede080f42b97b594fb14102c82ca1001b80c/src/backend/utils/adt/rangetypes.c#L2046

                let mut start = None;
                let mut end = None;

                let s = value.as_str()?;

                // remember the bounds
                let sb = s.as_bytes();
                let lower = sb[0] as char;
                let upper = sb[sb.len() - 1] as char;

                // trim the wrapping braces/brackets
                let s = &s[1..(s.len() - 1)];

                let mut chars = s.chars();

                let mut element = String::new();
                let mut done = false;
                let mut quoted = false;
                let mut in_quotes = false;
                let mut in_escape = false;
                let mut prev_ch = '\0';
                let mut count = 0;

                while !done {
                    element.clear();

                    loop {
                        match chars.next() {
                            Some(ch) => {
                                match ch {
                                    _ if in_escape => {
                                        element.push(ch);
                                        in_escape = false;
                                    }

                                    '"' if in_quotes => {
                                        in_quotes = false;
                                    }

                                    '"' => {
                                        in_quotes = true;
                                        quoted = true;

                                        if prev_ch == '"' {
                                            element.push('"')
                                        }
                                    }

                                    '\\' if !in_escape => {
                                        in_escape = true;
                                    }

                                    ',' if !in_quotes => break,

                                    _ => {
                                        element.push(ch);
                                    }
                                }
                                prev_ch = ch;
                            }

                            None => {
                                done = true;
                                break;
                            }
                        }
                    }

                    count += 1;
                    if !element.is_empty() || quoted {
                        let value = Some(T::decode(PgValueRef {
                            type_info: T::type_info(),
                            format: PgValueFormat::Text,
                            value: Some(element.as_bytes()),
                            row: None,
                        })?);

                        if count == 1 {
                            start = value;
                        } else if count == 2 {
                            end = value;
                        } else {
                            return Err("more than 2 elements found in a range".into());
                        }
                    }
                }

                let start = parse_bound(lower, start)?;
                let end = parse_bound(upper, end)?;

                Ok(PgRange { start, end })
            }
        }
    }
}

fn parse_bound<T>(ch: char, value: Option<T>) -> Result<Bound<T>, BoxDynError> {
    Ok(if let Some(value) = value {
        match ch {
            '(' | ')' => Bound::Excluded(value),
            '[' | ']' => Bound::Included(value),

            _ => {
                return Err(format!(
                    "expected `(`, ')', '[', or `]` but found `{ch}` for range literal"
                )
                .into());
            }
        }
    } else {
        Bound::Unbounded
    })
}

impl<T> Display for PgRange<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.start {
            Bound::Unbounded => f.write_str("(,")?,
            Bound::Excluded(v) => write!(f, "({v},")?,
            Bound::Included(v) => write!(f, "[{v},")?,
        }

        match &self.end {
            Bound::Unbounded => f.write_str(")")?,
            Bound::Excluded(v) => write!(f, "{v})")?,
            Bound::Included(v) => write!(f, "{v}]")?,
        }

        Ok(())
    }
}


impl PgHasRangeType for i32 {
    fn range_type_info() -> PgTypeInfo {
        PgTypeInfo::INT4_RANGE
    }

    fn range_array_type_info() -> PgTypeInfo {
        PgTypeInfo::INT4_RANGE_ARRAY
    }
}

impl PgHasRangeType for i64 {
    fn range_type_info() -> PgTypeInfo {
        PgTypeInfo::INT8_RANGE
    }

    fn range_array_type_info() -> PgTypeInfo {
        PgTypeInfo::INT8_RANGE_ARRAY
    }
}

#[cfg(feature = "bigdecimal")]
impl PgHasRangeType for bigdecimal::BigDecimal {
    fn range_type_info() -> PgTypeInfo {
        PgTypeInfo::NUM_RANGE
    }

    fn range_array_type_info() -> PgTypeInfo {
        PgTypeInfo::NUM_RANGE_ARRAY
    }
}

#[cfg(feature = "rust_decimal")]
impl PgHasRangeType for rust_decimal::Decimal {
    fn range_type_info() -> PgTypeInfo {
        PgTypeInfo::NUM_RANGE
    }

    fn range_array_type_info() -> PgTypeInfo {
        PgTypeInfo::NUM_RANGE_ARRAY
    }
}

#[cfg(feature = "chrono")]
impl PgHasRangeType for chrono::NaiveDate {
    fn range_type_info() -> PgTypeInfo {
        PgTypeInfo::DATE_RANGE
    }

    fn range_array_type_info() -> PgTypeInfo {
        PgTypeInfo::DATE_RANGE_ARRAY
    }
}

#[cfg(feature = "chrono")]
impl PgHasRangeType for chrono::NaiveDateTime {
    fn range_type_info() -> PgTypeInfo {
        PgTypeInfo::TS_RANGE
    }

    fn range_array_type_info() -> PgTypeInfo {
        PgTypeInfo::TS_RANGE_ARRAY
    }
}

#[cfg(feature = "chrono")]
impl<Tz: chrono::TimeZone> PgHasRangeType for chrono::DateTime<Tz> {
    fn range_type_info() -> PgTypeInfo {
        PgTypeInfo::TSTZ_RANGE
    }

    fn range_array_type_info() -> PgTypeInfo {
        PgTypeInfo::TSTZ_RANGE_ARRAY
    }
}

#[cfg(feature = "time")]
impl PgHasRangeType for time::Date {
    fn range_type_info() -> PgTypeInfo {
        PgTypeInfo::DATE_RANGE
    }

    fn range_array_type_info() -> PgTypeInfo {
        PgTypeInfo::DATE_RANGE_ARRAY
    }
}

#[cfg(feature = "time")]
impl PgHasRangeType for time::PrimitiveDateTime {
    fn range_type_info() -> PgTypeInfo {
        PgTypeInfo::TS_RANGE
    }

    fn range_array_type_info() -> PgTypeInfo {
        PgTypeInfo::TS_RANGE_ARRAY
    }
}

#[cfg(feature = "time")]
impl PgHasRangeType for time::OffsetDateTime {
    fn range_type_info() -> PgTypeInfo {
        PgTypeInfo::TSTZ_RANGE
    }

    fn range_array_type_info() -> PgTypeInfo {
        PgTypeInfo::TSTZ_RANGE_ARRAY
    }
}
