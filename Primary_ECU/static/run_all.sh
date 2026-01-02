#!/bin/bash
set -euo pipefail

ARCHIVE_PATH="${1:-${ARCHIVE:-}}"
OUT="${2:-./static_out}"

if [[ -z "$ARCHIVE_PATH" ]]; then
  echo "[!] Usage: $0 <oci-archive.tar> [out_dir]  (or set ARCHIVE env var)"
  exit 1
fi
if [[ ! -f "$ARCHIVE_PATH" ]]; then
  echo "[!] Archive not found: $ARCHIVE_PATH"
  exit 1
fi

mkdir -p "$OUT"

echo "[SBOM] Generating SBOM..."
bash ./static/sbom.sh "$ARCHIVE_PATH" > "$OUT/sbom.json"

echo "[CVE] Running CVE scan..."
bash ./static/cve_scan.sh "$ARCHIVE_PATH" > "$OUT/cve.log"

echo "[LICENSE] Checking licenses..."
bash ./static/license_scan.sh "$ARCHIVE_PATH" > "$OUT/license.log"

echo "[FS] Filesystem scan..."
bash ./static/fs_scan.sh "$ARCHIVE_PATH" "$OUT" > "$OUT/fs.log"