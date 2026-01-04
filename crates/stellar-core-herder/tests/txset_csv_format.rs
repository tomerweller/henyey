use std::fs;
use std::path::PathBuf;

fn testdata_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("..");
    path.push("testdata");
    path.push("txset");
    path.push(name);
    path
}

fn load_lines(name: &str) -> Vec<String> {
    let path = testdata_path(name);
    let payload = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    payload
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

#[test]
fn test_txset_csv_headers_and_columns() {
    let expected_header = "xdr_hash,total_fees,total_inclusion_fees,classic_ops,classic_non_dex_txs,classic_non_dex_txs_base_fee,classic_dex_txs,classic_dex_txs_base_fee,soroban_ops,soroban_base_fee,insns,disk_read_bytes,write_bytes,disk_read_entries,write_entries,tx_size_bytes";
    let files = ["v_prev.csv", "v_curr.csv", "v_next.csv"];

    for name in files {
        let lines = load_lines(name);
        assert!(!lines.is_empty(), "missing csv data in {}", name);
        assert_eq!(lines[0], expected_header, "header mismatch in {}", name);
        assert_eq!(
            lines.len(),
            50,
            "unexpected row count in {}",
            name
        );
        for (idx, line) in lines.iter().enumerate().skip(1) {
            let parts: Vec<&str> = line.split(',').collect();
            assert_eq!(
                parts.len(),
                16,
                "row {} has wrong column count in {}",
                idx,
                name
            );
            let hash = parts[0];
            assert_eq!(hash.len(), 64, "row {} hash length mismatch in {}", idx, name);
            assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "row {} hash not hex in {}", idx, name);
        }
    }
}
