//! XDR byte-level conversion helpers between workspace (v26) and P25 (v25) types.
//!
//! The `soroban-env-host-p25` crate uses `stellar-xdr` v25, while the workspace
//! uses v26. These types are structurally identical for the XDR types we use, so
//! we convert via serialization round-trip.

use soroban_env_host_p25 as soroban_host;

/// Convert a workspace (v26) type to a P25 (v25) type via XDR bytes.
///
/// Returns `None` if serialization or deserialization fails.
pub(super) fn ws_to_p25<WS, P25>(ws_val: &WS) -> Option<P25>
where
    WS: stellar_xdr::curr::WriteXdr,
    P25: soroban_host::xdr::ReadXdr,
{
    let bytes = ws_val.to_xdr(stellar_xdr::curr::Limits::none()).ok()?;
    P25::from_xdr(&bytes, soroban_host::xdr::Limits::none()).ok()
}

/// Like [`ws_to_p25`], but returns a `Result<P25, String>` with a descriptive
/// error message that includes the type name.
pub(super) fn ws_to_p25_result<WS, P25>(ws_val: &WS, type_name: &str) -> Result<P25, String>
where
    WS: stellar_xdr::curr::WriteXdr,
    P25: soroban_host::xdr::ReadXdr,
{
    ws_to_p25(ws_val).ok_or_else(|| format!("failed to convert {} to P25 XDR", type_name))
}

/// Convert a P25 (v25) type to a workspace (v26) type via XDR bytes.
///
/// Returns `None` if serialization or deserialization fails.
pub(super) fn p25_to_ws<P25, WS>(p25_val: &P25) -> Option<WS>
where
    P25: soroban_host::xdr::WriteXdr,
    WS: stellar_xdr::curr::ReadXdr,
{
    let bytes = p25_val.to_xdr(soroban_host::xdr::Limits::none()).ok()?;
    WS::from_xdr(&bytes, stellar_xdr::curr::Limits::none()).ok()
}

/// Like [`p25_to_ws`], but returns a `Result<WS, String>` with a descriptive
/// error message that includes the type name.
pub(super) fn p25_to_ws_result<P25, WS>(p25_val: &P25, type_name: &str) -> Result<WS, String>
where
    P25: soroban_host::xdr::WriteXdr,
    WS: stellar_xdr::curr::ReadXdr,
{
    p25_to_ws(p25_val).ok_or_else(|| format!("failed to convert {} from P25 XDR", type_name))
}
