## Pseudocode: crates/history/src/archive.rs

"History Archive client for accessing Stellar history archives.
 Supports fetching archive state, downloading ledger headers,
 transactions, and buckets."

---

### HistoryArchive (struct)

```
STRUCT HistoryArchive:
  base_url : URL
  client   : HTTP client
  config   : DownloadConfig
```

### new

```
function new(base_url):
  → with_config(base_url, DownloadConfig.default())
```

### with_config

```
function with_config(base_url, config):
  url = parse_url(base_url)
  // "Parse and normalize URL (ensure trailing slash)"
  if not url.path ends_with "/":
    url.path = url.path + "/"

  client = create_client(config.timeout)
    REF: download::create_client

  → HistoryArchive { base_url: url, client, config }
```

### base_url

```
function base_url(self):
  → self.base_url
```

### get_root_has

"The root HAS is located at .well-known/stellar-history.json"

```
async function get_root_has(self):
  url = self.make_url(root_has_path())
  bytes = download_with_retries(self.client, url, self.config)
    REF: download::download_with_retries
  text = bytes_to_utf8(bytes)
  → HistoryArchiveState.from_json(text)
    REF: archive_state::HistoryArchiveState::from_json
```

### get_checkpoint_has

```
async function get_checkpoint_has(self, ledger):
  path = checkpoint_path("history", ledger, "json")
    REF: paths::checkpoint_path
  url = self.make_url(path)
  bytes = download_with_retries(self.client, url, self.config)
  text = bytes_to_utf8(bytes)
  → HistoryArchiveState.from_json(text)
```

### get_ledger_headers

```
async function get_ledger_headers(self, checkpoint):
  path = checkpoint_path("ledger", checkpoint, "xdr.gz")
  data = self.download_xdr_gz(path)
  → parse_record_marked_xdr_stream(data)
    REF: download::parse_record_marked_xdr_stream
```

### get_transactions

```
async function get_transactions(self, checkpoint):
  path = checkpoint_path("transactions", checkpoint, "xdr.gz")
  data = self.download_xdr_gz(path)
  → parse_record_marked_xdr_stream(data)
```

### get_results

```
async function get_results(self, checkpoint):
  path = checkpoint_path("results", checkpoint, "xdr.gz")
  data = self.download_xdr_gz(path)
  → parse_record_marked_xdr_stream(data)
```

### get_scp_history

```
async function get_scp_history(self, checkpoint):
  path = checkpoint_path("scp", checkpoint, "xdr.gz")
  data = self.download_xdr_gz(path)
  → parse_record_marked_xdr_stream(data)
```

### get_bucket

```
async function get_bucket(self, hash):
  // "Skip zero hash (empty bucket)"
  GUARD hash.is_zero()  → empty bytes

  path = bucket_path(hash)    REF: paths::bucket_path
  → self.download_xdr_gz(path)
```

### Helper: download_xdr_gz

```
async function download_xdr_gz(self, path):
  url = self.make_url(path)
  compressed = download_with_retries(
    self.client, url, self.config)
  → decompress_gzip(compressed)
    REF: download::decompress_gzip
```

### Helper: make_url

```
function make_url(self, path):
  → self.base_url.join(path)
```

### check_accessible

```
async function check_accessible(self):
  self.get_root_has()
  → ok
```

### get_current_ledger

```
async function get_current_ledger(self):
  has = self.get_root_has()
  → has.current_ledger()
```

### get_ledger_header

```
async function get_ledger_header(self, seq):
  (header, _hash) = self.get_ledger_header_with_hash(seq)
  → header
```

### get_ledger_header_with_hash

"Downloads the checkpoint containing the ledger and extracts
 the specific header along with its archive hash."

```
async function get_ledger_header_with_hash(self, seq):
  headers = self.get_ledger_headers(seq)

  for each entry in headers:
    if entry.header.ledger_seq == seq:
      → (entry.header, entry.hash)

  → error NotFound("Ledger header {seq} not found")
```

### get_transaction_set

```
async function get_transaction_set(self, seq):
  transactions = self.get_transactions(seq)

  for each entry in transactions:
    if entry.ledger_seq == seq:
      → entry.tx_set

  // "Return empty transaction set if no transactions"
  → empty TransactionSet
```

---

## Network Constants

```
CONST testnet::ARCHIVE_URLS = [
  "https://history.stellar.org/prd/core-testnet/core_testnet_001",
  "https://history.stellar.org/prd/core-testnet/core_testnet_002",
  "https://history.stellar.org/prd/core-testnet/core_testnet_003",
]
CONST testnet::NETWORK_PASSPHRASE =
  "Test SDF Network ; September 2015"

CONST mainnet::ARCHIVE_URLS = [
  "https://history.stellar.org/prd/core-live/core_live_001",
  "https://history.stellar.org/prd/core-live/core_live_002",
  "https://history.stellar.org/prd/core-live/core_live_003",
]
CONST mainnet::NETWORK_PASSPHRASE =
  "Public Global Stellar Network ; September 2015"
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 399    | 118        |
| Functions     | 16     | 16         |
