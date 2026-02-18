## Pseudocode: crates/history/src/paths.rs

"History archives use a hierarchical path structure with hex-encoded
 ledger sequences for sharding across directories."

```
CONST CHECKPOINT_FREQUENCY = 64
```

---

### checkpoint_ledger

"Checkpoint ledgers are of the form (n * 64) + 63, i.e., 63, 127, 191, etc.
 Rounds a ledger sequence to its corresponding checkpoint."

```
function checkpoint_ledger(seq):
  → (seq / CHECKPOINT_FREQUENCY) * CHECKPOINT_FREQUENCY
    + (CHECKPOINT_FREQUENCY - 1)
```

### is_checkpoint_ledger

```
function is_checkpoint_ledger(seq):
  → (seq + 1) % CHECKPOINT_FREQUENCY == 0
```

### checkpoint_path

"Path format: {category}/{xx}/{yy}/{zz}/{category}-{hex}.{ext}
 where {xx}/{yy}/{zz} are the first three bytes of the
 hex-encoded checkpoint ledger."

```
function checkpoint_path(category, ledger, ext):
  checkpoint = checkpoint_ledger(ledger)
  hex = format_hex_8(checkpoint)

  → "{category}/{hex[0:2]}/{hex[2:4]}/{hex[4:6]}"
    + "/{category}-{hex}.{ext}"
```

### bucket_path

"Path format: bucket/{xx}/{yy}/{zz}/bucket-{hash}.xdr.gz
 where {xx}/{yy}/{zz} are the first three bytes of the hash."

```
function bucket_path(hash):
  hex = hash.to_hex()

  → "bucket/{hex[0:2]}/{hex[2:4]}/{hex[4:6]}"
    + "/bucket-{hex}.xdr.gz"
```

### root_has_path

```
function root_has_path():
  → ".well-known/stellar-history.json"
```

### ledger_dir

```
function ledger_dir(ledger):
  checkpoint = checkpoint_ledger(ledger)
  hex = format_hex_8(checkpoint)

  → "ledger/{hex[0:2]}/{hex[2:4]}/{hex[4:6]}"
```

### checkpoint_file_path

"Returns path without extension: {category}/{xx}/{yy}/{zz}/{category}-{hex}"

```
function checkpoint_file_path(ledger, file_type):
  checkpoint = checkpoint_ledger(ledger)
  hex = format_hex_8(checkpoint)

  → "{file_type}/{hex[0:2]}/{hex[2:4]}/{hex[4:6]}"
    + "/{file_type}-{hex}"
```

### has_path

```
function has_path(ledger):
  → checkpoint_path("history", ledger, "json")
```

---

## Dirty file helpers

"Dirty files are used during checkpoint building for crash safety.
 The checkpoint builder writes to .dirty files first, then atomically
 renames them to final paths on commit."

### checkpoint_path_dirty

```
function checkpoint_path_dirty(category, ledger, ext):
  → checkpoint_path(category, ledger, ext) + ".dirty"
```

### is_dirty_path

```
function is_dirty_path(path):
  name = file_name(path)
  GUARD name is nil                    → false
  → name ends_with ".dirty" AND length(name) > 6
```

### dirty_to_final_path

```
function dirty_to_final_path(dirty_path):
  s = path_to_string(dirty_path)
  GUARD s does not end with ".dirty"   → nil
  → strip_suffix(s, ".dirty")
```

### final_to_dirty_path

```
function final_to_dirty_path(final_path):
  name = file_name(final_path)
  → set_file_name(final_path, name + ".dirty")
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 241    | 66         |
| Functions     | 11     | 11         |
