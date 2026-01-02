//! Short hash utilities (SipHash-2-4).

use crate::random;
use crate::CryptoError;
use siphasher::sip::SipHasher24;
use std::hash::Hasher;
use std::sync::{Mutex, OnceLock};
use stellar_xdr::curr::{Limits, WriteXdr};

const KEY_BYTES: usize = 16;

#[derive(Clone)]
struct KeyState {
    key: [u8; KEY_BYTES],
    have_hashed: bool,
    explicit_seed: u32,
}

impl KeyState {
    fn new() -> Self {
        Self {
            key: random::random_bytes(),
            have_hashed: false,
            explicit_seed: 0,
        }
    }
}

fn key_state() -> &'static Mutex<KeyState> {
    static STATE: OnceLock<Mutex<KeyState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(KeyState::new()))
}

/// Initialize the short hash key with random bytes.
pub fn initialize() {
    let mut state = key_state().lock().expect("short hash lock poisoned");
    state.key = random::random_bytes();
}

/// Seed the short hash key for deterministic tests.
pub fn seed(seed: u32) -> Result<(), CryptoError> {
    let mut state = key_state().lock().expect("short hash lock poisoned");
    if state.have_hashed && state.explicit_seed != seed {
        return Err(CryptoError::ShortHashSeedConflict {
            existing: state.explicit_seed,
            requested: seed,
        });
    }
    state.explicit_seed = seed;
    for (i, byte) in state.key.iter_mut().enumerate() {
        let shift = i % std::mem::size_of::<u32>();
        *byte = (seed >> shift) as u8;
    }
    Ok(())
}

#[cfg(test)]
fn seed_key(seed: u32) -> [u8; KEY_BYTES] {
    let mut key = [0u8; KEY_BYTES];
    for (i, byte) in key.iter_mut().enumerate() {
        let shift = i % std::mem::size_of::<u32>();
        *byte = (seed >> shift) as u8;
    }
    key
}

/// Compute a SipHash-2-4 short hash for raw bytes.
pub fn compute_hash(bytes: &[u8]) -> u64 {
    let mut state = key_state().lock().expect("short hash lock poisoned");
    state.have_hashed = true;
    let mut hasher = SipHasher24::new_with_key(&state.key);
    hasher.write(bytes);
    hasher.finish()
}

/// Compute a SipHash-2-4 short hash for XDR-encoded values.
pub fn xdr_compute_hash<T: WriteXdr>(value: &T) -> Result<u64, CryptoError> {
    let bytes = value.to_xdr(Limits::none())?;
    Ok(compute_hash(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::LedgerEntry;

    fn reset_state() {
        let mut state = key_state().lock().expect("short hash lock poisoned");
        *state = KeyState::new();
    }

    fn compute_hash_with_key(key: [u8; KEY_BYTES], bytes: &[u8]) -> u64 {
        let mut hasher = SipHasher24::new_with_key(&key);
        hasher.write(bytes);
        hasher.finish()
    }

    #[test]
    fn test_siphash_vector() {
        reset_state();
        let key: [u8; KEY_BYTES] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let msg = [0u8; 0];
        let got = compute_hash_with_key(key, &msg);
        let expected = 0x726fdb47dd0e0e31u64;
        assert_eq!(got, expected);
    }

    #[test]
    fn test_xdr_hash_matches_bytes() {
        reset_state();
        initialize();
        let entry = LedgerEntry::default();
        let bytes = entry.to_xdr(Limits::none()).unwrap();
        let bytes_hash = compute_hash(&bytes);
        let xdr_hash = xdr_compute_hash(&entry).unwrap();
        assert_eq!(bytes_hash, xdr_hash);
    }

    #[test]
    fn test_seed_matches_upstream_key_derivation() {
        reset_state();
        let seed_value = 0x12345678;
        seed(seed_value).expect("seed");
        let key = seed_key(seed_value);
        let expected = compute_hash_with_key(key, b"");
        let got = compute_hash(b"");
        assert_eq!(got, expected);
    }

    #[test]
    fn test_seed_conflict_after_hash() {
        reset_state();
        initialize();
        let _ = compute_hash(b"warmup");
        let err = seed(1).expect_err("seed should fail");
        match err {
            CryptoError::ShortHashSeedConflict { existing, requested } => {
                assert_eq!(existing, 0);
                assert_eq!(requested, 1);
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_seed_repeat_is_allowed() {
        reset_state();
        seed(99).expect("seed");
        let _ = compute_hash(b"first");
        seed(99).expect("repeat seed");
    }
}
