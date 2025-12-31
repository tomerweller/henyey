//! Time utilities for rs-stellar-core.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Get the current Unix timestamp in seconds.
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Get the current Unix timestamp in milliseconds.
pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

/// Convert a timestamp to a SystemTime.
pub fn timestamp_to_system_time(timestamp: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(timestamp)
}

/// Stellar epoch (January 1, 2000 00:00:00 UTC).
pub const STELLAR_EPOCH: u64 = 946684800;

/// Convert Unix timestamp to Stellar timestamp.
pub fn unix_to_stellar_time(unix_ts: u64) -> u64 {
    unix_ts.saturating_sub(STELLAR_EPOCH)
}

/// Convert Stellar timestamp to Unix timestamp.
pub fn stellar_to_unix_time(stellar_ts: u64) -> u64 {
    stellar_ts.saturating_add(STELLAR_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_timestamp() {
        let ts = current_timestamp();
        // Should be after 2024
        assert!(ts > 1704067200);
    }

    #[test]
    fn test_stellar_time_conversion() {
        let unix_ts = 1704067200u64; // 2024-01-01 00:00:00 UTC
        let stellar_ts = unix_to_stellar_time(unix_ts);
        let back = stellar_to_unix_time(stellar_ts);
        assert_eq!(unix_ts, back);
    }
}
