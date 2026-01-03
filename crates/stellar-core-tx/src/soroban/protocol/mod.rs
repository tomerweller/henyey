//! Protocol-versioned Soroban host implementations.
//!
//! This module provides protocol-versioned implementations of the Soroban host
//! to ensure deterministic replay across protocol upgrades. Each protocol version
//! has its own implementation that uses the exact same soroban-env-host version
//! as C++ stellar-core.
//!
//! The dispatch is done at runtime based on the ledger's protocol version.

pub mod p24;
mod types;

pub use types::*;

use stellar_core_common::{protocol_version_is_before, ProtocolVersion};
use crate::soroban::SorobanConfig;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use stellar_xdr::curr::{AccountId, HostFunction, SorobanAuthorizationEntry, SorobanTransactionData};
use soroban_env_host::HostError;

/// Execute a host function using the appropriate protocol-versioned host.
///
/// This function dispatches to the correct soroban-env-host version based on
/// the ledger's protocol version.
pub fn execute_host_function(
    host_function: &HostFunction,
    auth_entries: &[SorobanAuthorizationEntry],
    source: &AccountId,
    state: &LedgerStateManager,
    context: &LedgerContext,
    soroban_data: &SorobanTransactionData,
    soroban_config: &SorobanConfig,
) -> Result<InvokeHostFunctionOutput, HostError> {
    let protocol_version = context.protocol_version;

    // Dispatch to the appropriate protocol-versioned host
    // Currently we only have p24, which handles protocols 20-24
    if protocol_version_is_before(protocol_version, ProtocolVersion::V25) {
        p24::invoke_host_function(
            host_function,
            auth_entries,
            source,
            state,
            context,
            soroban_data,
            soroban_config,
        )
    } else {
        // Protocol 25+: not yet implemented
        // TODO: Add p25 implementation when needed
        Err(HostError::from(soroban_env_host::Error::from_type_and_code(
            soroban_env_host::xdr::ScErrorType::Context,
            soroban_env_host::xdr::ScErrorCode::InternalError,
        )))
    }
}
