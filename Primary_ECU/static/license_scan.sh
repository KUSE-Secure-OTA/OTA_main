#!/bin/bash
set -euo pipefail

ARCHIVE_PATH="$1"
if [[ ! -f "$ARCHIVE_PATH" ]]; then
  echo "[!] Archive not found: $ARCHIVE_PATH" >&2
  exit 1
fi

# License scan (JSON). Policy will FAIL on disallowed licenses.
trivy image --input "$ARCHIVE_PATH" \
  --scanners license \
  --format json