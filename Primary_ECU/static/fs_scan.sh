#!/bin/bash
set -euo pipefail

ARCHIVE_PATH="$1"
if [[ ! -f "$ARCHIVE_PATH" ]]; then
  echo "[!] Archive not found: $ARCHIVE_PATH" >&2
  exit 1
fi

# IMPORTANT: Do NOT extract rootfs on vehicle.
# Use image-level secret scanning to avoid huge overhead.
trivy image --input "$ARCHIVE_PATH" \
  --scanners secret \
  --format json