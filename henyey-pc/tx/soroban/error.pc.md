## Pseudocode: crates/tx/src/soroban/error.rs

"Convert P24 HostError / ScError types to their P25 equivalents."

### convert_host_error_p24_to_p25

```
function convert_host_error_p24_to_p25(err):
  sc_error = extract ScError from err
    or default to Context(InternalError)
  sc_error = convert_sc_error_p24_to_p25(sc_error)
  → new HostError from sc_error
```

### Helper: convert_sc_error_code_p24_to_p25

```
function convert_sc_error_code_p24_to_p25(code):
  → cast code integer to P25 ScErrorCode
    or default to InternalError
```

### Helper: convert_sc_error_p24_to_p25

```
function convert_sc_error_p24_to_p25(sc_error):
  "Map each ScError variant, converting its code"
  if variant is Contract(code):
    → Contract(code)               // code is u32, no conversion
  if variant is WasmVm(code):
    → WasmVm(convert_sc_error_code_p24_to_p25(code))
  if variant is Context(code):
    → Context(convert_sc_error_code_p24_to_p25(code))
  if variant is Storage(code):
    → Storage(convert_sc_error_code_p24_to_p25(code))
  if variant is Object(code):
    → Object(convert_sc_error_code_p24_to_p25(code))
  if variant is Crypto(code):
    → Crypto(convert_sc_error_code_p24_to_p25(code))
  if variant is Events(code):
    → Events(convert_sc_error_code_p24_to_p25(code))
  if variant is Budget(code):
    → Budget(convert_sc_error_code_p24_to_p25(code))
  if variant is Value(code):
    → Value(convert_sc_error_code_p24_to_p25(code))
  if variant is Auth(code):
    → Auth(convert_sc_error_code_p24_to_p25(code))
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 45     | 30         |
| Functions     | 3      | 3          |
