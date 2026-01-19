#!/bin/bash
set -euo pipefail

ARCHIVE_PATH="$1"
if [[ ! -f "$ARCHIVE_PATH" ]]; then
  echo "[!] Archive not found: $ARCHIVE_PATH" >&2
  exit 1
fi

# SBOM (CycloneDX JSON)
trivy image --input "$ARCHIVE_PATH" --format cyclonedx