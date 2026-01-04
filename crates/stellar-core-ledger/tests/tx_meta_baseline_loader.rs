use std::fs;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::Value;

fn baseline_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.upstream-v25/test-tx-meta-baseline-current")
}

fn load_json(path: &PathBuf) -> Value {
    let data = fs::read_to_string(path).expect("read baseline json");
    serde_json::from_str(&data).expect("parse baseline json")
}

#[test]
fn test_upstream_tx_meta_baseline_headers() {
    let dir = baseline_dir();
    assert!(dir.is_dir(), "baseline directory missing: {}", dir.display());

    for entry in fs::read_dir(dir).expect("read baseline dir") {
        let entry = entry.expect("read baseline entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let root = load_json(&path);
        let protocol_version = root
            .get("!cfg protocol version")
            .and_then(Value::as_u64)
            .expect("protocol version");
        assert_eq!(protocol_version, 25, "protocol version mismatch in {}", path.display());

        let rng_seed = root.get("!rng seed").and_then(Value::as_u64).expect("rng seed");
        assert_eq!(rng_seed, 12345, "rng seed mismatch in {}", path.display());

        let all_versions = root
            .get("!test all versions")
            .and_then(Value::as_bool)
            .expect("test all versions");
        assert!(all_versions, "expected all versions enabled in {}", path.display());

        let versions = root
            .get("!versions to test")
            .and_then(Value::as_array)
            .expect("versions list");
        let expected: Vec<u64> = (0..=25).collect();
        let got: Vec<u64> = versions
            .iter()
            .map(|v| v.as_u64().expect("version value"))
            .collect();
        assert_eq!(
            got,
            expected,
            "unexpected versions list in {}",
            path.display()
        );
    }
}

#[test]
fn test_upstream_tx_meta_baseline_hash_format() {
    let dir = baseline_dir();
    assert!(dir.is_dir(), "baseline directory missing: {}", dir.display());

    for entry in fs::read_dir(dir).expect("read baseline dir") {
        let entry = entry.expect("read baseline entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let root = load_json(&path);
        let obj = root.as_object().expect("baseline json object");
        for (key, value) in obj {
            if key.starts_with('!') {
                continue;
            }
            let hashes = value.as_array().expect("hash list");
            for encoded in hashes {
                let encoded = encoded.as_str().expect("hash string");
                let decoded = STANDARD.decode(encoded).expect("decode base64 hash");
                assert_eq!(
                    decoded.len(),
                    8,
                    "expected 8-byte hash in {}:{}",
                    path.display(),
                    key
                );
            }
        }
    }
}
