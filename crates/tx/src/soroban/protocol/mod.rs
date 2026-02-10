//! Protocol-versioned Soroban host implementations.
//!
//! This module provides protocol-versioned implementations of the Soroban host
//! to ensure deterministic replay across protocol upgrades. Each protocol version
//! has its own implementation that uses the exact same soroban-env-host version
//! as stellar-core.
//!
//! The dispatch is done at runtime based on the ledger's protocol version.

pub mod p24;
pub mod p25;
mod types;

pub use types::*;

use crate::soroban::SorobanConfig;
use crate::state::LedgerStateManager;
use crate::validation::LedgerContext;
use soroban_env_host_p25::HostError as HostErrorP25;
use henyey_common::{protocol_version_is_before, ProtocolVersion};
use stellar_xdr::curr::{
    AccountId, HostFunction, SorobanAuthorizationEntry, SorobanTransactionData,
};

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
) -> Result<InvokeHostFunctionOutput, HostErrorP25> {
    let protocol_version = context.protocol_version;

    // Dispatch to the appropriate protocol-versioned host
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
        p25::invoke_host_function(
            host_function,
            auth_entries,
            source,
            state,
            context,
            soroban_data,
            soroban_config,
        )
    }
}
