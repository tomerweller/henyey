## Pseudocode: crates/app/src/catchup_cmd.rs

### Data: CatchupOptions

```
CatchupOptions:
  target: string          // "current" or ledger number
  mode: CatchupMode       // Minimal | Complete | Recent(n)
  verify: boolean
  parallelism: integer
  keep_temp: boolean

DEFAULTS:
  target = "current"
  mode = Minimal
  verify = true
  parallelism = 8
  keep_temp = false
```

### CatchupOptions::parse_target_and_mode

"Mode precedence (highest to lowest):
1. Explicit mode from CLI (if not default Minimal)
2. Mode from target string (e.g., '1000000/100' -> Recent(100))
3. Default (Minimal)"

```
function parse_target_and_mode(self):
  parsed = parse_target_with_mode(self.target)

  if self.mode != Minimal:
    effective_mode = self.mode
  else:
    effective_mode = parsed.mode_from_target or Minimal

  -> (parsed.target, effective_mode)
```

### parse_target_with_mode

"Formats:
- 'current' -> CatchupTarget::Current, None
- '12345' -> CatchupTarget::Ledger(12345), None
- '12345/100' -> CatchupTarget::Ledger(12345), Some(Recent(100))
- '12345/max' -> CatchupTarget::Ledger(12345), Some(Complete)"

```
function parse_target_with_mode(target_str):
  target = lowercase(trim(target_str))

  if target == "current" or target == "latest":
    -> (Current, no_mode)

  if target contains "/":
    ledger_str, count_str = split at "/"
    ledger = parse_integer(ledger_str)

    if count_str == "max":
      mode = Complete
    else:
      count = parse_integer(count_str)
      if count == 0:
        mode = Minimal
      else:
        mode = Recent(count)

    -> (Ledger(ledger), mode)

  ledger = parse_integer(target)
  -> (Ledger(ledger), no_mode)
```

### run_catchup

```
async function run_catchup(config, options):
  (target, effective_mode) = options.parse_target_and_mode()

  app = App.new(config)               REF: app/mod::App::new

  print_catchup_info(options, target, effective_mode)

  result = app.catchup_with_mode(target, effective_mode)
                                       REF: app/mod::App::catchup_with_mode

  print_catchup_result(result)

  if options.verify:
    verify_catchup(result)

  -> result
```

### verify_catchup

```
function verify_catchup(result):
  NOTE: placeholder — full implementation would:
  "1. Verify the bucket list hash
   2. Verify the ledger header hash chain
   3. Verify account balances sum correctly
   4. Run invariant checks"
```

### Interface: CatchupProgressCallback

```
interface CatchupProgressCallback:
  on_phase_change(phase: string)
  on_progress(current: u64, total: u64, message: string)
  on_complete(result: CatchupResult)
  on_error(error: string)
```

### ConsoleProgressCallback::on_progress

```
function on_progress(current, total, message):
  elapsed = time_since(start_time)
  if total > 0:
    percent = (current / total) * 100
    filled = percent / 100 * BAR_WIDTH
    render progress bar with elapsed, filled, percent, message
  else:
    print elapsed, message, current
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~296   | ~75        |
| Functions     | 12     | 7          |
