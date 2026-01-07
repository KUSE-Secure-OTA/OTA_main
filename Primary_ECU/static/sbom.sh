# Primary_ECU/static/sbom.sh
#!/bin/bash
set -euo pipefail

ARCHIVE_PATH="$1"
if [[ ! -f "$ARCHIVE_PATH" ]]; then
  echo "[!] Archive not found: $ARCHIVE_PATH"
  exit 1
fi

# 컨테이너 이미지 분석, SBOM을 CycloneDX JSON 포맷으로 출력
trivy image --input "$ARCHIVE_PATH" --format cyclonedx