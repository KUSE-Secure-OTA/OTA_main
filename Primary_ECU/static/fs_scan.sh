#!/bin/bash
set -euo pipefail

ARCHIVE_PATH="$1"
OUT="${2:-./static_out}"
WORK="${WORK_DIR:-$OUT/fs_work}"
ROOT="$WORK/rootfs"

if [[ ! -f "$ARCHIVE_PATH" ]]; then
  echo "[!] Archive not found: $ARCHIVE_PATH" >&2
  exit 1
fi

mkdir -p "$ROOT"
mkdir -p "$OUT"

echo "[+] podman load (for filesystem extraction only) ..." >&2

# podman load 전후 이미지 목록을 비교해서 새로 추가된 이미지 ID 수정
BEFORE_IDS="$(podman images --noheading --format '{{.Id}}' | sort || true)"
LOAD_OUT="$(podman load -i "$ARCHIVE_PATH")"
echo "$LOAD_OUT" >&2
AFTER_IDS="$(podman images --noheading --format '{{.Id}}' | sort || true)"

IMAGE_ID="$(comm -13 <(echo "$BEFORE_IDS") <(echo "$AFTER_IDS") | head -n 1 || true)"

# 위 방식 실패 시, podman load 출력에서 한번 더 파싱 시도
if [[ -z "${IMAGE_ID:-}" ]]; then
  IMAGE_ID="$(echo "$LOAD_OUT" | awk -F': ' '/Loaded image/ {print $2}' | tail -n1 || true)"
fi

if [[ -z "${IMAGE_ID:-}" ]]; then
  echo "[!] Failed to resolve loaded image ID" >&2
  exit 1
fi

echo "[+] Extracting container filesystem..." >&2

# create -> export -> tar extract 방식으로 rootfs 추출
CID="$(podman create "$IMAGE_ID")"
# 종료 시점에 이미지 정리
trap 'podman rm -f "$CID" >/dev/null 2>&1 || true; podman rmi -f "$IMAGE_ID" >/dev/null 2>&1 || true' EXIT

rm -rf "$ROOT"
mkdir -p "$ROOT"
podman export "$CID" | tar -x -C "$ROOT"

# 파일시스템 디렉토리 스캔
echo "[+] Running trivy fs (secret scanner)..." >&2
trivy fs "$ROOT" \
  --scanners secret \
  --format json
  
# malicious marker는 파일로 저장
echo "[+] Grep malicious markers..." >&2
grep -RInE \
  "curl[[:space:]]+[^|]+[[:space:]]*\|[[:space:]]*bash|wget[[:space:]]+[^|]+[[:space:]]*\|[[:space:]]*bash|nc[[:space:]]+[^[:space:]]+[[:space:]]+4444[[:space:]]+-e[[:space:]]*/bin/(ba)?sh" \
  "$ROOT" > "$OUT/malicious_hits.txt" || true