## Pseudocode: crates/history/src/error.rs

### HistoryError (enum)

"Error types for history operations."
"Errors are categorized by their source:
 - Network errors: HTTP failures, timeouts, unavailable archives
 - Parsing errors: Malformed XDR, JSON, or URL data
 - Verification errors: Hash mismatches, broken chains, invalid sequences
 - Catchup errors: Process failures during synchronization"

```
ENUM HistoryError:
  // Network / archive connectivity
  ArchiveUnreachable(message)
  NoArchiveAvailable
  ArchiveNotFound(name)
  ArchiveNotWritable(name)
  ArchiveAlreadyInitialized(name)

  // HTTP layer
  Http(inner_error)
  HttpStatus { url, status_code }
  NotFound(url)
  DownloadFailed(message)
  InvalidResponse(message)

  // Parsing
  UrlParse(inner_error)
  Json(inner_error)
  Xdr(inner_error)
  XdrParsing(message)
  Io(inner_error)

  // Verification / integrity
  CheckpointNotFound(seq)
  VerificationFailed(message)
  InvalidSequence { expected, got }
  InvalidPreviousHash { ledger }
  InvalidTxSetHash { ledger }
  NotCheckpointLedger(seq)

  // Catchup
  CatchupFailed(message)
  UnsupportedMode(message)

  // Domain-specific subsystems
  BucketNotFound(hash)
  Bucket(inner_error)
  Database(inner_error)

  // Remote archive commands
  RemoteNotConfigured(message)
  RemoteCommandFailed { command, exit_code, stderr }
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 155    | 34         |
| Functions     | 0      | 0          |

NOTE: This file defines only an error enum with no logic functions.
All variants carry context for diagnostics. Several variants wrap
errors from downstream crates (bucket, database, HTTP, XDR, JSON, IO).
