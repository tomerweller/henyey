//! Asset utilities for validation and conversion.
//!
//! This module provides functions for working with Stellar assets, including
//! validation, comparison, and string conversion utilities that match the
//! stellar-core implementation.
//!
//! # Examples
//!
//! ```rust
//! use henyey_common::asset::is_string_valid;
//!
//! // Check if string is valid for Stellar
//! assert!(is_string_valid("Hello World"));
//! assert!(!is_string_valid("Hello\x00World")); // Contains control character
//! ```

use stellar_xdr::curr::{
    AccountId, Asset, AssetCode12, AssetCode4, BucketEntry, ChangeTrustAsset,
    HotArchiveBucketEntry, LedgerEntry, LedgerKey, TrustLineAsset,
};

use crate::protocol::{protocol_version_is_before, protocol_version_starts_from, ProtocolVersion};

/// The fee for liquidity pools (30 basis points = 0.3%).
pub const LIQUIDITY_POOL_FEE_V18: i32 = 30;

// ============================================================================
// ASCII Utilities
// ============================================================================

/// Check if a character is a printable ASCII non-control character.
///
/// Returns true for characters in the range 0x20-0x7E (space through tilde).
#[inline]
pub fn is_ascii_non_control(c: char) -> bool {
    matches!(c, ' '..='~')
}

/// Check if a string contains only valid ASCII non-control characters.
///
/// This is used to validate strings in Stellar data entries and other
/// user-provided text fields.
///
/// # Examples
///
/// ```rust
/// use henyey_common::asset::is_string_valid;
///
/// assert!(is_string_valid("Hello World!"));
/// assert!(is_string_valid("test@example.com"));
/// assert!(!is_string_valid("hello\nworld")); // Newline is control char
/// assert!(!is_string_valid("hello\x00")); // Null is control char
/// ```
pub fn is_string_valid(s: &str) -> bool {
    s.chars().all(is_ascii_non_control)
}

// ============================================================================
// Asset Code Conversion
// ============================================================================

/// Convert an asset code byte array to a string.
///
/// Reads bytes until a null byte is encountered or the end of the array.
///
/// # Examples
///
/// ```rust
/// use henyey_common::asset::asset_code_to_str;
///
/// let code = [b'U', b'S', b'D', 0];
/// assert_eq!(asset_code_to_str(&code), "USD");
///
/// let code12 = [b'M', b'Y', b'T', b'O', b'K', b'E', b'N', 0, 0, 0, 0, 0];
/// assert_eq!(asset_code_to_str(&code12), "MYTOKEN");
/// ```
pub fn asset_code_to_str<const N: usize>(code: &[u8; N]) -> String {
    let len = code.iter().position(|&b| b == 0).unwrap_or(N);
    String::from_utf8_lossy(&code[..len]).into_owned()
}

/// Convert a string to an asset code byte array.
///
/// Copies the string into the array, padding with zeros if necessary.
/// If the string is longer than the array, it is truncated.
///
/// # Examples
///
/// ```rust
/// use henyey_common::asset::str_to_asset_code;
///
/// let code: [u8; 4] = str_to_asset_code("USD");
/// assert_eq!(&code, b"USD\0");
///
/// let code12: [u8; 12] = str_to_asset_code("MYTOKEN");
/// assert_eq!(&code12, b"MYTOKEN\0\0\0\0\0");
/// ```
pub fn str_to_asset_code<const N: usize>(s: &str) -> [u8; N] {
    let mut result = [0u8; N];
    let n = std::cmp::min(N, s.len());
    result[..n].copy_from_slice(&s.as_bytes()[..n]);
    result
}

/// Convert an Asset to its string representation.
///
/// Returns "XLM" for native assets, or the asset code for credit assets.
///
/// # Panics
///
/// Panics if the asset type is ASSET_TYPE_POOL_SHARE (not valid for Asset).
///
/// # Examples
///
/// ```rust
/// use henyey_common::asset::asset_to_string;
/// use stellar_xdr::curr::{Asset, AssetCode4, AlphaNum4, PublicKey, Uint256};
///
/// // Native asset
/// let native = Asset::Native;
/// assert_eq!(asset_to_string(&native), "XLM");
/// ```
pub fn asset_to_string(asset: &Asset) -> String {
    match asset {
        Asset::Native => "XLM".to_string(),
        Asset::CreditAlphanum4(alpha4) => asset_code_to_str(&alpha4.asset_code.0),
        Asset::CreditAlphanum12(alpha12) => asset_code_to_str(&alpha12.asset_code.0),
    }
}

// ============================================================================
// Asset Validation
// ============================================================================

/// Validate an asset code byte slice: all non-zero bytes must be ASCII
/// alphanumeric, zeros may only be trailing, and `char_count >= min_chars`.
fn is_asset_code_valid(code: &[u8], min_chars: usize) -> bool {
    let mut zeros = false;
    let mut char_count = 0;

    for &b in code {
        if b == 0 {
            zeros = true;
        } else if zeros {
            // zeros can only be trailing
            return false;
        } else if b > 0x7f || !(b as char).is_ascii_alphanumeric() {
            return false;
        } else {
            char_count += 1;
        }
    }
    char_count >= min_chars
}

/// Validate an asset code (alphaNum4): at least 1 alphanumeric character,
/// zeros only trailing.
fn is_asset_code4_valid(code: &AssetCode4) -> bool {
    is_asset_code_valid(&code.0, 1)
}

/// Validate an asset code (alphaNum12): at least 5 alphanumeric characters,
/// zeros only trailing.
fn is_asset_code12_valid(code: &AssetCode12) -> bool {
    is_asset_code_valid(&code.0, 5)
}

/// Check if an Asset is valid for the given protocol version.
///
/// # Examples
///
/// ```rust
/// use henyey_common::asset::is_asset_valid;
/// use stellar_xdr::curr::Asset;
///
/// // Native assets are always valid
/// assert!(is_asset_valid(&Asset::Native, 25));
/// ```
pub fn is_asset_valid(asset: &Asset, _ledger_version: u32) -> bool {
    match asset {
        Asset::Native => true,
        Asset::CreditAlphanum4(alpha4) => is_asset_code4_valid(&alpha4.asset_code),
        Asset::CreditAlphanum12(alpha12) => is_asset_code12_valid(&alpha12.asset_code),
    }
}

/// Check if a TrustLineAsset is valid for the given protocol version.
pub fn is_trustline_asset_valid(asset: &TrustLineAsset, ledger_version: u32) -> bool {
    match asset {
        TrustLineAsset::Native => true,
        TrustLineAsset::CreditAlphanum4(alpha4) => is_asset_code4_valid(&alpha4.asset_code),
        TrustLineAsset::CreditAlphanum12(alpha12) => is_asset_code12_valid(&alpha12.asset_code),
        TrustLineAsset::PoolShare(_) => {
            protocol_version_starts_from(ledger_version, ProtocolVersion::V18)
        }
    }
}

/// Check if a ChangeTrustAsset is valid for the given protocol version.
pub fn is_change_trust_asset_valid(asset: &ChangeTrustAsset, ledger_version: u32) -> bool {
    match asset {
        ChangeTrustAsset::Native => true,
        ChangeTrustAsset::CreditAlphanum4(alpha4) => is_asset_code4_valid(&alpha4.asset_code),
        ChangeTrustAsset::CreditAlphanum12(alpha12) => is_asset_code12_valid(&alpha12.asset_code),
        ChangeTrustAsset::PoolShare(lp) => {
            if protocol_version_is_before(ledger_version, ProtocolVersion::V18) {
                return false;
            }

            let stellar_xdr::curr::LiquidityPoolParameters::LiquidityPoolConstantProduct(cp) = lp;

            is_asset_valid(&cp.asset_a, ledger_version)
                && is_asset_valid(&cp.asset_b, ledger_version)
                && cp.asset_a < cp.asset_b
                && cp.fee == LIQUIDITY_POOL_FEE_V18
        }
    }
}

// ============================================================================
// Issuer Utilities
// ============================================================================

/// Error returned when trying to get the issuer of a native asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoIssuerError;

impl std::fmt::Display for NoIssuerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "asset does not have an issuer")
    }
}

impl std::error::Error for NoIssuerError {}

/// Get the issuer of an asset.
///
/// # Errors
///
/// Returns `NoIssuerError` for native assets.
///
/// # Examples
///
/// ```rust
/// use henyey_common::asset::get_issuer;
/// use stellar_xdr::curr::Asset;
///
/// // Native assets have no issuer
/// assert!(get_issuer(&Asset::Native).is_err());
/// ```
pub fn get_issuer(asset: &Asset) -> Result<&AccountId, NoIssuerError> {
    match asset {
        Asset::CreditAlphanum4(alpha4) => Ok(&alpha4.issuer),
        Asset::CreditAlphanum12(alpha12) => Ok(&alpha12.issuer),
        Asset::Native => Err(NoIssuerError),
    }
}

/// Get the issuer of a TrustLineAsset.
pub fn get_trustline_asset_issuer(asset: &TrustLineAsset) -> Result<&AccountId, NoIssuerError> {
    match asset {
        TrustLineAsset::CreditAlphanum4(alpha4) => Ok(&alpha4.issuer),
        TrustLineAsset::CreditAlphanum12(alpha12) => Ok(&alpha12.issuer),
        TrustLineAsset::Native | TrustLineAsset::PoolShare(_) => Err(NoIssuerError),
    }
}

/// Check if an account is the issuer of an asset.
///
/// Returns false for native assets.
pub fn is_issuer(acc: &AccountId, asset: &Asset) -> bool {
    get_issuer(asset).is_ok_and(|issuer| issuer == acc)
}

/// Check if an account is the issuer of a TrustLineAsset.
pub fn is_trustline_asset_issuer(acc: &AccountId, asset: &TrustLineAsset) -> bool {
    get_trustline_asset_issuer(asset).is_ok_and(|issuer| issuer == acc)
}

// ============================================================================
// Balance Utilities
// ============================================================================

/// Add a delta to a balance, checking for overflow and underflow.
///
/// # Arguments
///
/// * `balance` - The current balance (must be non-negative)
/// * `delta` - The amount to add (can be negative)
/// * `max_balance` - The maximum allowed balance
///
/// # Returns
///
/// Returns `Some(new_balance)` if the operation is valid, or `None` if:
/// - The result would be negative
/// - The result would exceed `max_balance`
///
/// # Panics
///
/// Panics if `balance` or `max_balance` is negative.
///
/// # Examples
///
/// ```rust
/// use henyey_common::asset::add_balance;
///
/// // Adding to balance
/// assert_eq!(add_balance(100, 50, i64::MAX), Some(150));
///
/// // Subtracting from balance
/// assert_eq!(add_balance(100, -50, i64::MAX), Some(50));
///
/// // Would go negative
/// assert_eq!(add_balance(100, -150, i64::MAX), None);
///
/// // Would exceed max
/// assert_eq!(add_balance(100, 50, 120), None);
/// ```
pub fn add_balance(balance: i64, delta: i64, max_balance: i64) -> Option<i64> {
    assert!(balance >= 0, "balance must be non-negative");
    assert!(max_balance >= 0, "max_balance must be non-negative");

    if delta == 0 {
        return Some(balance);
    }

    // Check if result would be negative
    // Equivalent to (balance + delta) < 0 without overflow
    if delta < -balance {
        return None;
    }

    // Check if result would exceed max
    // Equivalent to (balance + delta) > max_balance without overflow
    if max_balance - balance < delta {
        return None;
    }

    Some(balance + delta)
}

// ============================================================================
// Bucket Entry Utilities
// ============================================================================

/// Get the ledger key from a HotArchiveBucketEntry.
///
/// # Panics
///
/// Panics for METAENTRY entries.
pub fn get_hot_archive_bucket_ledger_key(be: &HotArchiveBucketEntry) -> LedgerKey {
    match be {
        HotArchiveBucketEntry::Archived(entry) => ledger_entry_key(entry),
        HotArchiveBucketEntry::Live(key) => key.clone(),
        HotArchiveBucketEntry::Metaentry(_) => {
            panic!("Tried to get key for METAENTRY")
        }
    }
}

/// Get the ledger key from a BucketEntry.
///
/// # Panics
///
/// Panics for METAENTRY entries.
pub fn get_bucket_ledger_key(be: &BucketEntry) -> LedgerKey {
    match be {
        BucketEntry::Liveentry(entry) | BucketEntry::Initentry(entry) => ledger_entry_key(entry),
        BucketEntry::Deadentry(key) => key.clone(),
        BucketEntry::Metaentry(_) => {
            panic!("Tried to get key for METAENTRY")
        }
    }
}

/// Extract the ledger key from a ledger entry.
pub fn ledger_entry_key(entry: &LedgerEntry) -> LedgerKey {
    use stellar_xdr::curr::LedgerEntryData;

    match &entry.data {
        LedgerEntryData::Account(a) => LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
            account_id: a.account_id.clone(),
        }),
        LedgerEntryData::Trustline(t) => {
            LedgerKey::Trustline(stellar_xdr::curr::LedgerKeyTrustLine {
                account_id: t.account_id.clone(),
                asset: t.asset.clone(),
            })
        }
        LedgerEntryData::Offer(o) => LedgerKey::Offer(stellar_xdr::curr::LedgerKeyOffer {
            seller_id: o.seller_id.clone(),
            offer_id: o.offer_id,
        }),
        LedgerEntryData::Data(d) => LedgerKey::Data(stellar_xdr::curr::LedgerKeyData {
            account_id: d.account_id.clone(),
            data_name: d.data_name.clone(),
        }),
        LedgerEntryData::ClaimableBalance(cb) => {
            LedgerKey::ClaimableBalance(stellar_xdr::curr::LedgerKeyClaimableBalance {
                balance_id: cb.balance_id.clone(),
            })
        }
        LedgerEntryData::LiquidityPool(lp) => {
            LedgerKey::LiquidityPool(stellar_xdr::curr::LedgerKeyLiquidityPool {
                liquidity_pool_id: lp.liquidity_pool_id.clone(),
            })
        }
        LedgerEntryData::ContractData(cd) => {
            LedgerKey::ContractData(stellar_xdr::curr::LedgerKeyContractData {
                contract: cd.contract.clone(),
                key: cd.key.clone(),
                durability: cd.durability,
            })
        }
        LedgerEntryData::ContractCode(cc) => {
            LedgerKey::ContractCode(stellar_xdr::curr::LedgerKeyContractCode {
                hash: cc.hash.clone(),
            })
        }
        LedgerEntryData::ConfigSetting(cs) => {
            LedgerKey::ConfigSetting(stellar_xdr::curr::LedgerKeyConfigSetting {
                config_setting_id: cs.discriminant(),
            })
        }
        LedgerEntryData::Ttl(t) => LedgerKey::Ttl(stellar_xdr::curr::LedgerKeyTtl {
            key_hash: t.key_hash.clone(),
        }),
    }
}

// ============================================================================
// Price Comparison
// ============================================================================

use stellar_xdr::curr::Price;

/// Compare two prices for greater-than-or-equal using cross-multiplication.
///
/// Uses 128-bit arithmetic to avoid overflow.
///
/// # Panics
///
/// Panics if any component is negative.
pub fn price_ge(a: &Price, b: &Price) -> bool {
    assert!(a.n >= 0 && a.d >= 0 && b.n >= 0 && b.d >= 0);

    let l = (a.n as u128) * (b.d as u128);
    let r = (a.d as u128) * (b.n as u128);
    l >= r
}

/// Compare two prices for greater-than using cross-multiplication.
///
/// Uses 128-bit arithmetic to avoid overflow.
///
/// # Panics
///
/// Panics if any component is negative.
pub fn price_gt(a: &Price, b: &Price) -> bool {
    assert!(a.n >= 0 && a.d >= 0 && b.n >= 0 && b.d >= 0);

    let l = (a.n as u128) * (b.d as u128);
    let r = (a.d as u128) * (b.n as u128);
    l > r
}

// ============================================================================
// Hash XOR Operations
// ============================================================================

use crate::Hash256;

/// XOR two hashes together, modifying the first in place.
impl std::ops::BitXorAssign for Hash256 {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a ^= b;
        }
    }
}

impl std::ops::BitXor for Hash256 {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self ^= rhs;
        self
    }
}

/// Compare two hashes with XOR distance to a third hash.
///
/// Returns true if `(l ^ x) < (r ^ x)` in lexicographic order.
pub fn less_than_xored(l: &Hash256, r: &Hash256, x: &Hash256) -> bool {
    (*l ^ *x).0 < (*r ^ *x).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{AlphaNum12, AlphaNum4, PublicKey, Uint256};

    fn make_account_id(n: u8) -> AccountId {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))
    }

    fn make_asset4(code: &str, issuer: u8) -> Asset {
        let mut code_bytes = [0u8; 4];
        code_bytes[..code.len().min(4)].copy_from_slice(&code.as_bytes()[..code.len().min(4)]);
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(code_bytes),
            issuer: make_account_id(issuer),
        })
    }

    fn make_asset12(code: &str, issuer: u8) -> Asset {
        let mut code_bytes = [0u8; 12];
        code_bytes[..code.len().min(12)].copy_from_slice(&code.as_bytes()[..code.len().min(12)]);
        Asset::CreditAlphanum12(AlphaNum12 {
            asset_code: AssetCode12(code_bytes),
            issuer: make_account_id(issuer),
        })
    }

    #[test]
    fn test_is_ascii_non_control() {
        assert!(is_ascii_non_control(' '));
        assert!(is_ascii_non_control('~'));
        assert!(is_ascii_non_control('A'));
        assert!(!is_ascii_non_control('\n'));
        assert!(!is_ascii_non_control('\0'));
        assert!(!is_ascii_non_control('\x7f'));
    }

    #[test]
    fn test_is_string_valid() {
        assert!(is_string_valid("Hello World!"));
        assert!(is_string_valid("test@example.com"));
        assert!(is_string_valid(" "));
        assert!(!is_string_valid("\n"));
        assert!(!is_string_valid("\0"));
        assert!(!is_string_valid("hello\x00world"));
    }

    #[test]
    fn test_asset_code_to_str() {
        assert_eq!(asset_code_to_str(&[b'U', b'S', b'D', 0]), "USD");
        assert_eq!(
            asset_code_to_str(&[b'U', b'S', b'D', b'C', 0, 0, 0, 0, 0, 0, 0, 0]),
            "USDC"
        );
        assert_eq!(asset_code_to_str(&[0, 0, 0, 0]), "");
    }

    #[test]
    fn test_str_to_asset_code() {
        let code4: [u8; 4] = str_to_asset_code("USD");
        assert_eq!(&code4, b"USD\0");

        let code12: [u8; 12] = str_to_asset_code("MYTOKEN");
        assert_eq!(&code12, b"MYTOKEN\0\0\0\0\0");
    }

    #[test]
    fn test_asset_to_string() {
        assert_eq!(asset_to_string(&Asset::Native), "XLM");
        assert_eq!(asset_to_string(&make_asset4("USD", 1)), "USD");
        assert_eq!(asset_to_string(&make_asset12("MYTOKEN", 1)), "MYTOKEN");
    }

    #[test]
    fn test_is_asset_valid() {
        // Native always valid
        assert!(is_asset_valid(&Asset::Native, 25));

        // Valid alphaNum4
        assert!(is_asset_valid(&make_asset4("USD", 1), 25));
        assert!(is_asset_valid(&make_asset4("X", 1), 25));

        // Valid alphaNum12
        assert!(is_asset_valid(&make_asset12("MYTOKEN", 1), 25)); // 7 chars
        assert!(is_asset_valid(&make_asset12("ABCDE", 1), 25)); // 5 chars - minimum

        // Invalid - empty code
        let empty4 = Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4([0, 0, 0, 0]),
            issuer: make_account_id(1),
        });
        assert!(!is_asset_valid(&empty4, 25));

        // Invalid alphaNum12 - too short (4 chars)
        assert!(!is_asset_valid(&make_asset12("ABCD", 1), 25));
    }

    #[test]
    fn test_get_issuer() {
        assert!(get_issuer(&Asset::Native).is_err());

        let usd = make_asset4("USD", 42);
        let issuer = get_issuer(&usd).unwrap();
        assert_eq!(issuer, &make_account_id(42));
    }

    #[test]
    fn test_is_issuer() {
        let account = make_account_id(42);
        let usd = make_asset4("USD", 42);
        let eur = make_asset4("EUR", 1);

        assert!(is_issuer(&account, &usd));
        assert!(!is_issuer(&account, &eur));
        assert!(!is_issuer(&account, &Asset::Native));
    }

    #[test]
    fn test_add_balance() {
        // Basic addition
        assert_eq!(add_balance(100, 50, i64::MAX), Some(150));

        // Basic subtraction
        assert_eq!(add_balance(100, -50, i64::MAX), Some(50));

        // Zero delta
        assert_eq!(add_balance(100, 0, i64::MAX), Some(100));

        // Would go negative
        assert_eq!(add_balance(100, -150, i64::MAX), None);

        // Would exceed max
        assert_eq!(add_balance(100, 50, 120), None);

        // Edge case: exact max
        assert_eq!(add_balance(100, 20, 120), Some(120));

        // Edge case: exact zero
        assert_eq!(add_balance(100, -100, i64::MAX), Some(0));
    }

    #[test]
    fn test_price_comparison() {
        let p1 = Price { n: 1, d: 2 }; // 0.5
        let p2 = Price { n: 2, d: 3 }; // 0.667
        let p3 = Price { n: 1, d: 2 }; // 0.5

        assert!(price_gt(&p2, &p1));
        assert!(!price_gt(&p1, &p2));
        assert!(!price_gt(&p1, &p3));

        assert!(price_ge(&p2, &p1));
        assert!(!price_ge(&p1, &p2));
        assert!(price_ge(&p1, &p3));
    }

    #[test]
    fn test_hash_xor() {
        let mut h1 = Hash256::from_bytes([0xff; 32]);
        let h2 = Hash256::from_bytes([0xff; 32]);
        h1 ^= h2;
        assert!(h1.is_zero());

        let h3 = Hash256::from_bytes([0x0f; 32]);
        let h4 = Hash256::from_bytes([0xf0; 32]);
        let result = h3 ^ h4;
        assert_eq!(result.0, [0xff; 32]);
    }

    #[test]
    fn test_less_than_xored() {
        let x = Hash256::from_bytes([0x80; 32]);
        let l = Hash256::from_bytes([0x00; 32]); // l ^ x = 0x80
        let r = Hash256::from_bytes([0x01; 32]); // r ^ x = 0x81

        assert!(less_than_xored(&l, &r, &x)); // 0x80 < 0x81
        assert!(!less_than_xored(&r, &l, &x)); // 0x81 > 0x80
    }
}
