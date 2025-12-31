//! Secure random number generation.

use rand::{rngs::OsRng, RngCore};

/// Generate random bytes.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generate a random 32-byte value.
pub fn random_bytes_32() -> [u8; 32] {
    random_bytes()
}

/// Generate a random 64-byte value.
pub fn random_bytes_64() -> [u8; 64] {
    random_bytes()
}

/// Generate a random u64.
pub fn random_u64() -> u64 {
    OsRng.next_u64()
}

/// Generate a random u32.
pub fn random_u32() -> u32 {
    OsRng.next_u32()
}

/// Fill a slice with random bytes.
pub fn fill_random(dest: &mut [u8]) {
    OsRng.fill_bytes(dest);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        let a: [u8; 32] = random_bytes();
        let b: [u8; 32] = random_bytes();

        // Should produce different values (with overwhelming probability)
        assert_ne!(a, b);
    }

    #[test]
    fn test_random_u64() {
        let a = random_u64();
        let b = random_u64();

        // Should produce different values (with overwhelming probability)
        assert_ne!(a, b);
    }

    #[test]
    fn test_fill_random() {
        let mut buf = [0u8; 32];
        fill_random(&mut buf);

        // Should not be all zeros
        assert_ne!(buf, [0u8; 32]);
    }
}
