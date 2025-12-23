#!/bin/bash
set -euo pipefail

ARCHIVE_PATH="$1"
OUT="${2:-./static_out}"
WORK="${WORK_DIR:-$OUT/fs_work}"
ROOT="$WORK/rootfs"

if [[ ! -f "$ARCHIVE_PATH" ]]; then
  echo "[!] Archive not found: $ARCHIVE_PATH"
  exit 1
fi

mkdir -p "$ROOT"

echo "[+] podman load (for filesystem extraction only) ..."

BEFORE_IDS="$(podman images --noheading --format '{{.Id}}' | sort || true)"
LOAD_OUT="$(podman load -i "$ARCHIVE_PATH")"
echo "$LOAD_OUT"
AFTER_IDS="$(podman images --noheading --format '{{.Id}}' | sort || true)"

IMAGE_ID="$(comm -13 <(echo "$BEFORE_IDS") <(echo "$AFTER_IDS") | head -n 1 || true)"

if [[ -z "${IMAGE_ID:-}" ]]; then
  IMAGE_ID="$(echo "$LOAD_OUT" | awk -F': ' '/Loaded image/ {print $2}' | tail -n1 || true)"
fi

if [[ -z "${IMAGE_ID:-}" ]]; then
  echo "[!] Failed to resolve loaded image ID"
  exit 1
fi

echo "[+] Extracting container filesystem..."
CID="$(podman create "$IMAGE_ID")"
trap 'podman rm -f "$CID" >/dev/null 2>&1 || true' EXIT

rm -rf "$ROOT"
mkdir -p "$ROOT"
podman export "$CID" | tar -x -C "$ROOT"

echo "[+] Running trivy fs ..."
trivy fs "$ROOT"

podman rmi -f "$IMAGE_ID" >/dev/null 2>&1 || true