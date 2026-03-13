//! Shared utility functions for the RPC crate.

use stellar_xdr::curr::{LedgerKey, Limits, WriteXdr};

/// Build the TTL lookup key for a contract data or contract code ledger key.
///
/// Returns `None` if the key is not a TTL-bearing type.
pub(crate) fn ttl_key_for_ledger_key(key: &LedgerKey) -> Option<LedgerKey> {
    match key {
        LedgerKey::ContractData(_) | LedgerKey::ContractCode(_) => {
            Some(LedgerKey::Ttl(stellar_xdr::curr::LedgerKeyTtl {
                key_hash: hash_ledger_key(key),
            }))
        }
        _ => None,
    }
}

/// SHA-256 hash of the XDR-encoded ledger key, returned as an XDR `Hash`.
pub(crate) fn hash_ledger_key(key: &LedgerKey) -> stellar_xdr::curr::Hash {
    let xdr_bytes = key.to_xdr(Limits::none()).expect("XDR encode");
    let hash = henyey_crypto::sha256(&xdr_bytes);
    stellar_xdr::curr::Hash(*hash.as_bytes())
}

/// Format a Unix timestamp as an ISO 8601 UTC string (e.g. `2024-01-15T12:30:00Z`).
pub(crate) fn format_unix_timestamp_utc(unix_ts: u64) -> String {
    let secs = unix_ts as i64;
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate year/month/day from days since 1970-01-01
    let mut days = days_since_epoch;
    let mut year = 1970i32;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let leap = is_leap_year(year);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    let mut month = 0usize;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md {
            month = i;
            break;
        }
        days -= md;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month + 1,
        days + 1,
        hours,
        minutes,
        seconds
    )
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}
