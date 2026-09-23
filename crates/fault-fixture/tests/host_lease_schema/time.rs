//! UTC timestamp parsing and wall/monotonic deadline arithmetic.
//!
//! `TimestampKey` keeps its parsed calendar fields private so the only way to
//! build one is the strict `timestamp_key` parser.

const NANOSECONDS_PER_SECOND: u128 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TimestampKey {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    nanosecond: u32,
}

fn digits(bytes: &[u8], context: &str) -> Result<u32, String> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(format!("{context} contains non-digit timestamp fields"));
    }
    Ok(bytes
        .iter()
        .fold(0_u32, |value, byte| value * 10 + u32::from(byte - b'0')))
}

pub fn timestamp_key(value: &str, context: &str) -> Result<TimestampKey, String> {
    let bytes = value.as_bytes();
    if !(20..=30).contains(&bytes.len())
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || bytes.last() != Some(&b'Z')
    {
        return Err(format!("{context} is not a UTC timestamp"));
    }
    let year = u16::try_from(digits(&bytes[0..4], context)?)
        .map_err(|_| format!("{context} year is out of range"))?;
    let month = u8::try_from(digits(&bytes[5..7], context)?)
        .map_err(|_| format!("{context} month is out of range"))?;
    let day = u8::try_from(digits(&bytes[8..10], context)?)
        .map_err(|_| format!("{context} day is out of range"))?;
    let hour = u8::try_from(digits(&bytes[11..13], context)?)
        .map_err(|_| format!("{context} hour is out of range"))?;
    let minute = u8::try_from(digits(&bytes[14..16], context)?)
        .map_err(|_| format!("{context} minute is out of range"))?;
    let second = u8::try_from(digits(&bytes[17..19], context)?)
        .map_err(|_| format!("{context} second is out of range"))?;
    if !(1..=12).contains(&month) || !(0..=23).contains(&hour) || minute > 59 || second > 59 {
        return Err(format!(
            "{context} contains an out-of-range timestamp field"
        ));
    }
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days_in_month = match month {
        2 if leap_year => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day == 0 || day > days_in_month {
        return Err(format!("{context} contains an out-of-range calendar day"));
    }
    let nanosecond = if bytes.len() == 20 {
        0
    } else {
        if bytes[19] != b'.' || !(1..=9).contains(&(bytes.len() - 21)) {
            return Err(format!("{context} has an invalid fractional second"));
        }
        let fraction = &bytes[20..bytes.len() - 1];
        if !fraction.iter().all(u8::is_ascii_digit) {
            return Err(format!("{context} has an invalid fractional second"));
        }
        let mut value = digits(fraction, context)?;
        for _ in 0..(9 - fraction.len()) {
            value *= 10;
        }
        value
    };
    Ok(TimestampKey {
        year,
        month,
        day,
        hour,
        minute,
        second,
        nanosecond,
    })
}

pub fn timestamp(value: &str, context: &str) -> Result<(), String> {
    timestamp_key(value, context).map(|_| ())
}

fn days_in_month(year: u16, month: u8) -> u8 {
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    match month {
        2 if leap_year => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn wall_nanos(value: TimestampKey) -> Result<u128, String> {
    let mut days = 0_u128;
    for year in 0..value.year {
        days = days
            .checked_add(if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                366
            } else {
                365
            })
            .ok_or_else(|| "wall-clock day overflow".to_owned())?;
    }
    for month in 1..value.month {
        days = days
            .checked_add(u128::from(days_in_month(value.year, month)))
            .ok_or_else(|| "wall-clock day overflow".to_owned())?;
    }
    days = days
        .checked_add(u128::from(value.day - 1))
        .ok_or_else(|| "wall-clock day overflow".to_owned())?;
    let seconds = days
        .checked_mul(86_400)
        .ok_or_else(|| "wall-clock second overflow".to_owned())?;
    let seconds = seconds
        .checked_add(u128::from(value.hour) * 3_600)
        .ok_or_else(|| "wall-clock second overflow".to_owned())?;
    let seconds = seconds
        .checked_add(u128::from(value.minute) * 60)
        .ok_or_else(|| "wall-clock second overflow".to_owned())?;
    let seconds = seconds
        .checked_add(u128::from(value.second))
        .ok_or_else(|| "wall-clock second overflow".to_owned())?;
    seconds
        .checked_mul(NANOSECONDS_PER_SECOND)
        .and_then(|seconds| seconds.checked_add(u128::from(value.nanosecond)))
        .ok_or_else(|| "wall-clock nanosecond overflow".to_owned())
}

pub fn derive_deadline(
    received_at_wall: TimestampKey,
    expires: TimestampKey,
    ttl_seconds: u64,
    received_at_monotonic: u64,
) -> Result<u64, String> {
    let received_nanos = wall_nanos(received_at_wall)?;
    let expires_nanos = wall_nanos(expires)?;
    let remaining_nanos = expires_nanos
        .checked_sub(received_nanos)
        .ok_or_else(|| "grant is expired at receipt".to_owned())?;
    if remaining_nanos == 0 {
        return Err("grant is expired at receipt".to_owned());
    }
    let ttl_nanos = u128::from(ttl_seconds)
        .checked_mul(NANOSECONDS_PER_SECOND)
        .ok_or_else(|| "TTL deadline overflow".to_owned())?;
    let bounded_nanos = remaining_nanos.min(ttl_nanos);
    let deadline = u128::from(received_at_monotonic)
        .checked_add(bounded_nanos)
        .ok_or_else(|| "monotonic deadline overflow".to_owned())?;
    u64::try_from(deadline).map_err(|_| "monotonic deadline overflow".to_owned())
}

pub fn monotonic_seconds(seconds: u64) -> u64 {
    seconds
        .checked_mul(1_000_000_000)
        .expect("test monotonic timestamp fits in nanoseconds")
}
