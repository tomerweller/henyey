#!/usr/bin/env bash
# Verify that spec-eval documents and README.md parity percentages are
# consistent with the stellar-core submodule version and each crate's
# PARITY_STATUS.md.
#
# Pass 1: Every docs/spec-eval/*_SPEC_HENYEY_EVAL.md must reference the
#          current stellar-core submodule tag in its first 10 lines.
# Pass 2: Every parity percentage in README.md's crate overview table must
#          match the corresponding crate's PARITY_STATUS.md.
#
# Usage: bash scripts/check-spec-eval-freshness.sh
set -euo pipefail

if [ ! -d "stellar-core/.git" ] && [ ! -f "stellar-core/.git" ]; then
    echo "ERROR: stellar-core submodule not initialized."
    echo "Run: git submodule update --init stellar-core"
    exit 1
fi

errors=0
warnings=0

echo "Checking spec-eval freshness..."

# --- Resolve stellar-core submodule tag ---
SC_TAG=$(git -C stellar-core describe --tags --exact-match HEAD 2>/dev/null || true)
if [ -z "$SC_TAG" ]; then
    # Fallback: parse parenthetical from git submodule status
    SC_TAG=$(git submodule status stellar-core 2>/dev/null \
        | sed -n 's/.*(\(.*\))/\1/p')
fi
if [ -z "$SC_TAG" ]; then
    echo "ERROR: cannot resolve stellar-core submodule tag."
    echo "The submodule HEAD does not point to an annotated tag."
    exit 1
fi
echo "  stellar-core submodule tag: $SC_TAG"
echo

# =========================================================================
# Pass 1: Version references in spec-eval docs
# =========================================================================
echo "Pass 1: Checking version references in spec-eval docs..."

shopt -s nullglob
spec_eval_files=( docs/spec-eval/*_SPEC_HENYEY_EVAL.md )
shopt -u nullglob
if [ ${#spec_eval_files[@]} -eq 0 ]; then
    echo "  WARNING: no *_SPEC_HENYEY_EVAL.md files found in docs/spec-eval/"
    warnings=$((warnings + 1))
else
    for f in "${spec_eval_files[@]}"; do
        basename=$(basename "$f")
        if head -10 "$f" | grep -qF "$SC_TAG"; then
            echo "  ✓ $basename"
        else
            echo "  ✗ $basename: expected '$SC_TAG' in header (first 10 lines)"
            errors=$((errors + 1))
        fi
    done
fi
echo

# =========================================================================
# Pass 2: README.md parity percentages vs PARITY_STATUS.md
# =========================================================================
echo "Pass 2: Checking README.md parity percentages..."

# Extract README references: pattern like [N%](crates/X/PARITY_STATUS.md)
readme_refs=$(grep -oP '\[(\d+)%\]\((crates/[^)]+/PARITY_STATUS\.md)\)' README.md || true)
readme_crates=()

while IFS= read -r match; do
    [ -z "$match" ] && continue
    readme_pct=$(echo "$match" | grep -oP '^\[(\d+)%' | tr -d '[%')
    parity_path=$(echo "$match" | grep -oP '\((.+)\)' | tr -d '()')

    if [ ! -f "$parity_path" ]; then
        echo "  ✗ $parity_path: file not found (referenced in README.md)"
        errors=$((errors + 1))
        continue
    fi

    # Extract Overall Parity from PARITY_STATUS.md
    actual_pct=$(grep -oP '\*\*Overall Parity\*\*:\s*(\d+)%' "$parity_path" \
        | grep -oP '\d+' || true)

    if [ -z "$actual_pct" ]; then
        echo "  ✗ $parity_path: could not extract '**Overall Parity**: N%'"
        errors=$((errors + 1))
        continue
    fi

    if [ "$readme_pct" != "$actual_pct" ]; then
        echo "  ✗ $parity_path: README says ${readme_pct}%, PARITY_STATUS says ${actual_pct}%"
        errors=$((errors + 1))
    else
        echo "  ✓ $parity_path: ${actual_pct}%"
    fi

    readme_crates+=("$parity_path")
done <<< "$readme_refs"

echo

# --- Coverage check: are all PARITY_STATUS.md files referenced? ---
# Exclusions: crates that are intentionally not in the README table.
EXCLUDED_CRATES="crates/invariant/PARITY_STATUS.md"

echo "Pass 2b: Checking PARITY_STATUS.md coverage in README..."
for ps in crates/*/PARITY_STATUS.md; do
    # Skip excluded crates
    if echo "$EXCLUDED_CRATES" | grep -qF "$ps"; then
        continue
    fi

    found=false
    for ref in "${readme_crates[@]}"; do
        if [ "$ref" = "$ps" ]; then
            found=true
            break
        fi
    done

    if [ "$found" = false ]; then
        echo "  ✗ $ps exists but is not referenced in README.md"
        errors=$((errors + 1))
    fi
done
echo

# =========================================================================
# Summary
# =========================================================================
if [ $warnings -gt 0 ]; then
    echo "$warnings warning(s)."
fi

if [ $errors -gt 0 ]; then
    echo "$errors error(s) found."
    exit 1
else
    echo "All checks passed."
    exit 0
fi
