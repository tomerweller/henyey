use serde_json::{Map, Value};
use stellar_core_history::archive_state::HistoryArchiveState;

fn normalize_json(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut normalized = Map::new();
            for (key, value) in map {
                let value = normalize_json(value);
                if !value.is_null() {
                    normalized.insert(key, value);
                }
            }
            Value::Object(normalized)
        }
        Value::Array(items) => {
            let mut normalized = Vec::new();
            for item in items {
                let item = normalize_json(item);
                if !item.is_null() {
                    normalized.push(item);
                }
            }
            Value::Array(normalized)
        }
        other => other,
    }
}

fn assert_roundtrip(name: &str, json: &str) {
    let has = HistoryArchiveState::from_json(json)
        .unwrap_or_else(|err| panic!("failed to parse {}: {}", name, err));
    let serialized = has
        .to_json()
        .unwrap_or_else(|err| panic!("failed to serialize {}: {}", name, err));

    let original_value = normalize_json(
        serde_json::from_str(json)
            .unwrap_or_else(|err| panic!("invalid json fixture {}: {}", name, err)),
    );
    let serialized_value = normalize_json(
        serde_json::from_str(&serialized)
            .unwrap_or_else(|err| panic!("invalid serialized json for {}: {}", name, err)),
    );

    assert_eq!(
        original_value, serialized_value,
        "serialized json mismatch for {}",
        name
    );
}

#[test]
fn test_history_archive_state_roundtrip() {
    let fixtures = [
        (
            "stellar-history.testnet.6714239.json",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/serialize-tests/stellar-history.testnet.6714239.json"
            )),
        ),
        (
            "stellar-history.livenet.15686975.json",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/serialize-tests/stellar-history.livenet.15686975.json"
            )),
        ),
        (
            "stellar-history.testnet.6714239.networkPassphrase.json",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/serialize-tests/stellar-history.testnet.6714239.networkPassphrase.json"
            )),
        ),
        (
            "stellar-history.testnet.6714239.networkPassphrase.v2.json",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/serialize-tests/stellar-history.testnet.6714239.networkPassphrase.v2.json"
            )),
        ),
    ];

    for (name, json) in fixtures {
        assert_roundtrip(name, json);
    }
}
