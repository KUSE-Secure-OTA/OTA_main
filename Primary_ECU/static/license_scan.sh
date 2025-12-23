#!/bin/bash
set -euo pipefail

ARCHIVE_PATH="$1"
if [[ ! -f "$ARCHIVE_PATH" ]]; then
  echo "[!] Archive not found: $ARCHIVE_PATH"
  exit 1
fi

trivy image --input "$ARCHIVE_PATH" --scanners license