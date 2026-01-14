#!/bin/bash
set -euo pipefail

ARCHIVE_ARG="${1:-${ARCHIVE:-}}"
OUT="${2:-./static_out}"

if [[ -z "${ARCHIVE_ARG}" ]]; then
  echo "[!] Usage: $0 <image-archive.tar> [out_dir]  (or set ARCHIVE env var)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resolve archive path
ARCHIVE_PATH="$ARCHIVE_ARG"
if [[ ! -f "$ARCHIVE_PATH" ]]; then
  if [[ -f "$SCRIPT_DIR/$ARCHIVE_ARG" ]]; then
    ARCHIVE_PATH="$SCRIPT_DIR/$ARCHIVE_ARG"
  elif [[ -f "$SCRIPT_DIR/images/$ARCHIVE_ARG" ]]; then
    ARCHIVE_PATH="$SCRIPT_DIR/images/$ARCHIVE_ARG"
  fi
fi

if [[ ! -f "$ARCHIVE_PATH" ]]; then
  echo "[!] Archive not found: $ARCHIVE_ARG" >&2
  echo "    Looked in: $(pwd), $SCRIPT_DIR, $SCRIPT_DIR/images" >&2
  exit 1
fi

mkdir -p "$OUT"

echo "[SBOM] Generating SBOM..." >&2
"$SCRIPT_DIR/sbom.sh" "$ARCHIVE_PATH" > "$OUT/sbom.json"

echo "[CVE] Running vulnerability scan (json)..." >&2
"$SCRIPT_DIR/cve_scan.sh" "$ARCHIVE_PATH" > "$OUT/cve.json"

echo "[LICENSE] Checking licenses (json)..." >&2
"$SCRIPT_DIR/license_scan.sh" "$ARCHIVE_PATH" > "$OUT/license.json"

echo "[SECRET] Running image-level secret scan (json)..." >&2
"$SCRIPT_DIR/fs_scan.sh" "$ARCHIVE_PATH" > "$OUT/fs.json"

echo "[POLICY] Evaluating policy..." >&2
# PASS/WARN => exit 0, FAIL => exit 2
python3 "$SCRIPT_DIR/evaluate_policy.py" "$OUT" --archive "$ARCHIVE_PATH" | tee "$OUT/policy.log" >/dev/null

echo "[DONE] Static verification finished -> $OUT" >&2