# Primary_ECU/static/run_all.sh
#!/bin/bash
set -euo pipefail

ARCHIVE_PATH="${1:-${ARCHIVE:-}}"
OUT="${2:-./static_out}"

if [[ -z "${ARCHIVE_PATH}" ]]; then
  echo "[!] Usage: $0 <oci-archive.tar> [out_dir]  (or set ARCHIVE env var)"
  exit 1
fi
if [[ ! -f "${ARCHIVE_PATH}" ]]; then
  echo "[!] Archive not found: ${ARCHIVE_PATH}"
  exit 1
fi

# cwd와 상관 없이 안정적으로 실행
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "${OUT}"

# Trivy image 스캐너로 CycloneDX SBOM을 생성해서 파일로 저장
echo "[SBOM] Generating SBOM..."
"${SCRIPT_DIR}/sbom.sh" "${ARCHIVE_PATH}" > "${OUT}/sbom.json"

# 취악점 스캔 결과
echo "[CVE] Running CVE scan (json)..."
"${SCRIPT_DIR}/cve_scan.sh" "${ARCHIVE_PATH}" > "${OUT}/cve.json"

# 라이선스 스캔 결과
echo "[LICENSE] Checking licenses (json)..."
"${SCRIPT_DIR}/license_scan.sh" "${ARCHIVE_PATH}" > "${OUT}/license.json"

# 컨테이너 rootfs 뽑고 fs 스캔 결과 저장
echo "[FS] Filesystem + secret scan (json) ..."
"${SCRIPT_DIR}/fs_scan.sh" "${ARCHIVE_PATH}" "${OUT}" > "${OUT}/fs.json"

# 정책 판단 결과 policy.log로 저장 -> evaluate_policy.py에서 추가 처리
echo "[POLICY] Evaluating policy..."
python3 "${SCRIPT_DIR}/evaluate_policy.py" "${OUT}" > "${OUT}/policy.log"

echo "[DONE] Static verification finished -> ${OUT}"