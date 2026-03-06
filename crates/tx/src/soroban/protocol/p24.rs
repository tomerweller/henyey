//! Protocol 24 Soroban host implementation.
//!
//! This module previously contained a standalone `invoke_host_function` entry point
//! for protocol 24. The production execution path is now exclusively through
//! `crate::soroban::host::execute_host_function_with_cache` → `execute_host_function_p24`,
//! which accepts an optional persistent module cache for improved performance.
