# Primary_ECU/static/cve_scan.sh
#!/bin/bash
set -euo pipefail

ARCHIVE_PATH="$1"
if [[ ! -f "$ARCHIVE_PATH" ]]; then
  echo "[!] Archive not found: $ARCHIVE_PATH"
  exit 1
fi

trivy image --input "$ARCHIVE_PATH" \
  --scanners vuln \                  # 취약점 스캐너만 활성화
  --severity HIGH,CRITICAL \         # HIGH/CRITICAL만 필터링
  --ignore-unfixed \                 # 아직 패치 없는 취약점은 무시 (실험 정책에 따라 조정 가능)
  --format json                      