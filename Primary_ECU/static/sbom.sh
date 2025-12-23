#!/bin/bash
set -euo pipefail

ARCHIVE_PATH="$1"
if [[ ! -f "$ARCHIVE_PATH" ]]; then
  echo "[!] Archive not found: $ARCHIVE_PATH"
  exit 1
fi

# stdout으로 CycloneDX JSON 출력
trivy image --input "$ARCHIVE_PATH" --format cyclonedx