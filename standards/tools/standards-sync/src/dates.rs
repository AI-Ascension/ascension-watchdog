//! Calendar-date parsing, comparison, and current-date evaluation.

use crate::Result;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn valid_date(value: &str) -> bool {
    date_parts(value).is_some()
}

pub(crate) fn valid_date_order(start: &str, end: &str) -> bool {
    match (date_days(start), date_days(end)) {
        (Ok(start), Ok(end)) => start <= end,
        _ => false,
    }
}

pub(crate) fn date_parts(value: &str) -> Option<(i32, u32, u32)> {
    let mut parts = value.split('-');
    let year = parts.next()?.parse::<i32>().ok()?;
    let month = parts.next()?.parse::<u32>().ok()?;
    let day = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some()
        || value.len() != 10
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
    {
        return None;
    }
    Some((year, month, day))
}

pub(crate) fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

pub(crate) fn date_days(value: &str) -> Result<i64> {
    let (year, month, day) = date_parts(value).ok_or_else(|| format!("invalid date '{value}'"))?;
    let adjusted_year = year - i32::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month as i32 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day as i32 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Ok(i64::from(era * 146097 + day_of_era - 719468))
}

pub(crate) fn as_of_days(as_of: Option<&str>) -> Result<i64> {
    match as_of {
        Some(value) => date_days(value),
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| (duration.as_secs() / 86_400) as i64)
            .map_err(|error| format!("cannot determine current UTC date: {error}")),
    }
}
