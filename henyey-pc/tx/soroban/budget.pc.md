## Pseudocode: crates/tx/src/soroban/budget.rs

"Soroban resource budget tracking."
"Tracks CPU instructions and memory usage for contract execution."

### Data Structures

```
struct SorobanConfig:
  cpu_cost_params                   // ContractCostParams
  mem_cost_params                   // ContractCostParams
  tx_max_instructions               // u64
  tx_max_memory_bytes               // u64
  min_temp_entry_ttl                // u32
  min_persistent_entry_ttl          // u32
  max_entry_ttl                     // u32
  fee_config                        // FeeConfiguration
  rent_fee_config                   // RentFeeConfiguration
  tx_max_contract_events_size_bytes // u32
  max_contract_size_bytes           // u32
  max_contract_data_entry_size_bytes // u32

  DEFAULTS:
    tx_max_instructions          = 100_000_000
    tx_max_memory_bytes          = 40 MB
    min_temp_entry_ttl           = 16
    min_persistent_entry_ttl     = 120960   // ~7 days
    max_entry_ttl                = 6312000  // ~1 year
    max_contract_size_bytes      = 64 KB
    max_contract_data_entry_size = 64 KB

enum BudgetError:
  CpuLimitExceeded
  MemoryLimitExceeded
  ReadLimitExceeded
  WriteLimitExceeded

struct ResourceLimits:
  cpu_instructions  // u64, default 100M
  memory_bytes      // u64, default 64 MB
  read_bytes        // u64, default 200 KB
  write_bytes       // u64, default 65 KB
  read_entries      // u32, default 40
  write_entries     // u32, default 25

struct SorobanBudget:
  cpu_used           // u64
  mem_used           // u64
  read_bytes_used    // u64
  write_bytes_used   // u64
  limits             // ResourceLimits
```

### SorobanConfig.has_valid_cost_params

```
function has_valid_cost_params(self):
  "Returns false if cost params are empty (placeholder values)."
  → self.cpu_cost_params is not empty
    AND self.mem_cost_params is not empty
```

### ResourceLimits.from_soroban_resources

```
function from_soroban_resources(resources):
  → ResourceLimits {
      cpu_instructions: resources.instructions,
      memory_bytes:     64 MB,  // fixed memory limit
      read_bytes:       resources.disk_read_bytes,
      write_bytes:      resources.write_bytes,
      read_entries:     len(resources.footprint.read_only),
      write_entries:    len(resources.footprint.read_write)
    }
```

### SorobanBudget.new

```
function new(limits):
  → SorobanBudget {
      cpu_used: 0, mem_used: 0,
      read_bytes_used: 0, write_bytes_used: 0,
      limits: limits
    }
```

### SorobanBudget.charge_cpu

```
function charge_cpu(self, instructions):
  MUTATE self cpu_used += instructions  (saturating)
  GUARD self.cpu_used > limits.cpu_instructions
    → BudgetError.CpuLimitExceeded
```

### SorobanBudget.charge_mem

```
function charge_mem(self, bytes):
  MUTATE self mem_used += bytes  (saturating)
  GUARD self.mem_used > limits.memory_bytes
    → BudgetError.MemoryLimitExceeded
```

### SorobanBudget.charge_read

```
function charge_read(self, bytes):
  MUTATE self read_bytes_used += bytes  (saturating)
  GUARD self.read_bytes_used > limits.read_bytes
    → BudgetError.ReadLimitExceeded
```

### SorobanBudget.charge_write

```
function charge_write(self, bytes):
  MUTATE self write_bytes_used += bytes  (saturating)
  GUARD self.write_bytes_used > limits.write_bytes
    → BudgetError.WriteLimitExceeded
```

### SorobanBudget.is_exhausted

```
function is_exhausted(self):
  → cpu_used > limits.cpu_instructions
    OR mem_used > limits.memory_bytes
    OR read_bytes_used > limits.read_bytes
    OR write_bytes_used > limits.write_bytes
```

### SorobanBudget.remaining_cpu

```
function remaining_cpu(self):
  → limits.cpu_instructions - cpu_used  (saturating)
```

### SorobanBudget.remaining_mem

```
function remaining_mem(self):
  → limits.memory_bytes - mem_used  (saturating)
```

### SorobanBudget.reset

```
function reset(self):
  MUTATE self cpu_used = 0
  MUTATE self mem_used = 0
  MUTATE self read_bytes_used = 0
  MUTATE self write_bytes_used = 0
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 271    | 92         |
| Functions     | 12     | 11         |
