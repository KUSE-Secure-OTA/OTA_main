#!/bin/bash
set -euo pipefail

ARCHIVE_PATH="$1"
if [[ ! -f "$ARCHIVE_PATH" ]]; then
  echo "[!] Archive not found: $ARCHIVE_PATH" >&2
  exit 1
fi

# Vulnerability scan (JSON). Policy will WARN only.
trivy image --input "$ARCHIVE_PATH" \
  --scanners vuln \
  --format json