from __future__ import annotations
import json, os, re, base64, binascii
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ✅ config에서 설정을 가져옴 (하드코딩 제거)
from config import (
    DIRECTOR_METADATA_DIR,
    DIRECTOR_KEYS_DIR,
    SNAPSHOT_EXPIRES_DAYS,
)

SPEC_VERSION = "1.0.0"  # 고정값은 유지해도 OK

# ---------- 유틸 ----------
def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def load_private_key(path: Path) -> Ed25519PrivateKey:
    if not path.exists():
        raise FileNotFoundError(f"Private key not found: {path}")
    return serialization.load_pem_private_key(path.read_bytes(), password=None)

def ed25519_sign_b64(sk: Ed25519PrivateKey, data: bytes) -> str:
    """서명 → base64 (targets와 인코딩 통일)"""
    return base64.b64encode(sk.sign(data)).decode("ascii")

def ed25519_pub_pem_to_raw_hex(pub_pem_path: Path) -> str:
    """공개키 PEM → RAW 32바이트 → hex 문자열."""
    if not pub_pem_path.exists():
        raise FileNotFoundError(f"Public key not found: {pub_pem_path}")
    pub = serialization.load_pem_public_key(pub_pem_path.read_bytes(), backend=default_backend())
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)  # 32 bytes
    return raw.hex()

def make_expires_iso8601_plus_days(days: int) -> str:
    # UTC 기준으로 바로 만료 설정 (Asia/Seoul 필요 없으면 단순화)
    exp_utc = datetime.now(timezone.utc) + timedelta(days=days)
    return exp_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

def latest_version_file(meta_dir: Path, pattern: str) -> Optional[Path]:
    """
    meta_dir 안에서 정규식 pattern과 매칭되는 파일 중
    가장 큰 버전(숫자 캡처 그룹 #1)을 가진 파일 Path 반환.
    예: pattern=r"^(\d+)\.targets\.json$"
    """
    if not meta_dir.is_dir():
        return None
    rx = re.compile(pattern)
    best_ver = -1
    best_path: Optional[Path] = None
    for name in os.listdir(meta_dir):
        m = rx.match(name)
        if not m:
            continue
        ver = int(m.group(1))
        if ver > best_ver:
            best_ver = ver
            best_path = meta_dir / name
    return best_path

def next_snapshot_version() -> int:
    latest = latest_version_file(DIRECTOR_METADATA_DIR, r"^(\d+)\.snapshot\.json$")
    if not latest:
        return 1
    return int(latest.stem.split(".")[0]) + 1

def latest_targets_version() -> int:
    """최근 <num>.targets.json의 num 반환 (없으면 1로 시작)"""
    latest = latest_version_file(DIRECTOR_METADATA_DIR, r"^(\d+)\.targets\.json$")
    if not latest:
        return 1
    return int(latest.stem.split(".")[0])

def latest_root_path() -> Path:
    """최근 <num>.root.json Path 반환 (없으면 에러)"""
    p = latest_version_file(DIRECTOR_METADATA_DIR, r"^(\d+)\.root\.json$")
    if not p:
        raise FileNotFoundError(f"No root.json found in {DIRECTOR_METADATA_DIR}")
    return p

def resolve_snapshot_keyid_from_root_by_pubhex(root_path: Path, my_pub_hex: str) -> str:
    root_doc = json.loads(root_path.read_text(encoding="utf-8"))
    signed = root_doc["signed"]
    keys = signed["keys"]                           # { keyid: keyobj }
    role_kids = signed["roles"]["snapshot"]["keyids"]  # [ keyid, ... ]
    for kid in role_kids:
        keyobj = keys[kid]
        if keyobj.get("keytype") == "ed25519" and keyobj.get("keyval", {}).get("public") == my_pub_hex:
            return kid
    raise RuntimeError("snapshot role 공개키가 root에 등록되어 있지 않습니다.")

def write_snapshot_json(version: int, doc: Dict[str, Any]) -> Path:
    out = DIRECTOR_METADATA_DIR / f"{version}.snapshot.json"
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return out

# ---------- 메인 ----------
def generate_snapshot() -> Path:
    """
    Snapshot 메타를 생성/서명하여 <version>.snapshot.json 에 저장하고 Path를 반환.
    - root/targes 최신 버전 자동 탐색
    - 키/경로/만료는 .env/config로 관리
    """
    version = next_snapshot_version()

    # 1) 내 공개키(hex)와 root의 snapshot role 매칭 → keyid 획득
    snapshot_pub_pem = DIRECTOR_KEYS_DIR / "snapshot_pub.pem"
    my_pub_hex = ed25519_pub_pem_to_raw_hex(snapshot_pub_pem)
    root_path = latest_root_path()
    snapshot_kid = resolve_snapshot_keyid_from_root_by_pubhex(root_path, my_pub_hex)

    # 2) targets 최신 버전
    targets_ver = latest_targets_version()
    meta_key = "targets.json"  # TUF snapshot.meta의 키 이름은 targets.json로 고정

    # 3) signed(snapshot) 구성
    expires = make_expires_iso8601_plus_days(SNAPSHOT_EXPIRES_DAYS)
    snapshot_signed: Dict[str, Any] = {
        "_type": "snapshot",
        "expires": expires,
        "meta": {meta_key: {"version": targets_ver}},
        "spec_version": SPEC_VERSION,
        "version": version,
    }

    # 4) 서명(base64로 통일)
    sk = load_private_key(DIRECTOR_KEYS_DIR / "snapshot.pem")
    payload = canonical_json_bytes(snapshot_signed)
    sig_b64 = ed25519_sign_b64(sk, payload)

    result: Dict[str, Any] = {
        "signatures": [{"keyid": snapshot_kid, "sig": sig_b64}],
        "signed": snapshot_signed,
    }

    # 5) 파일 저장 후 Path 반환
    return write_snapshot_json(version, result)
