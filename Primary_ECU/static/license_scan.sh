# Primary_ECU/static/license_scan.sh
#!/bin/bash
set -euo pipefail

ARCHIVE_PATH="$1"
if [[ ! -f "$ARCHIVE_PATH" ]]; then
  echo "[!] Archive not found: $ARCHIVE_PATH"
  exit 1
fi

# 라이선스 스캐너 활성화
trivy image --input "$ARCHIVE_PATH" \
  --scanners license \
  --format json