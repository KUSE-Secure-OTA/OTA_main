from __future__ import annotations
import os, re, json, base64, hashlib
from typing import Any, Dict, Optional
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ✅ config에서 설정 로드 (경로/만료/키)
from config import (
    DIRECTOR_METADATA_DIR,
    DIRECTOR_KEYS_DIR,
    TIMESTAMP_EXPIRES_DAYS,
)

SPEC_VERSION = "1.0.0"  # 고정 상수

# ---------- 유틸 ----------
def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def load_private_key(path: Path) -> Ed25519PrivateKey:
    if not path.exists():
        raise FileNotFoundError(f"Private key not found: {path}")
    return serialization.load_pem_private_key(path.read_bytes(), password=None)

def ed25519_sign_b64(sk: Ed25519PrivateKey, data: bytes) -> str:
    return base64.b64encode(sk.sign(data)).decode("ascii")

def ed25519_pub_pem_to_raw_hex(pub_pem_path: Path) -> str:
    if not pub_pem_path.exists():
        raise FileNotFoundError(f"Public key not found: {pub_pem_path}")
    pub = serialization.load_pem_public_key(pub_pem_path.read_bytes(), backend=default_backend())
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)  # 32 bytes
    return raw.hex()

def iso_utc_after_days(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

def latest_version_file(meta_dir: Path, pattern: str) -> Optional[Path]:
    """
    meta_dir 안에서 정규식 pattern과 매칭되는 파일 중
    가장 큰 버전(숫자 캡처 #1)을 가진 파일 Path 반환.
    예: r"^(\d+)\.snapshot\.json$"
    """
    if not meta_dir.is_dir():
        return None
    rx = re.compile(pattern)
    best_ver, best_path = -1, None
    for name in os.listdir(meta_dir):
        m = rx.match(name)
        if not m:
            continue
        ver = int(m.group(1))
        if ver > best_ver:
            best_ver, best_path = ver, meta_dir / name
    return best_path

def latest_root_path() -> Path:
    p = latest_version_file(DIRECTOR_METADATA_DIR, r"^(\d+)\.root\.json$")
    if not p:
        raise FileNotFoundError(f"No root.json found in {DIRECTOR_METADATA_DIR}")
    return p

def latest_snapshot_path() -> Optional[Path]:
    return latest_version_file(DIRECTOR_METADATA_DIR, r"^(\d+)\.snapshot\.json$")

def next_timestamp_version() -> int:
    latest = latest_version_file(DIRECTOR_METADATA_DIR, r"^(\d+)\.timestamp\.json$")
    return 1 if not latest else int(latest.stem.split(".")[0]) + 1

def resolve_timestamp_keyid_from_root_by_pubhex(root_path: Path, my_pub_hex: str) -> str:
    root_doc = json.loads(root_path.read_text(encoding="utf-8"))
    signed = root_doc["signed"]
    keys = signed["keys"]                                  # { keyid: keyobj }
    role_kids = signed["roles"]["timestamp"]["keyids"]     # [ keyid, ... ]
    for kid in role_kids:
        keyobj = keys[kid]
        if keyobj.get("keytype") == "ed25519" and keyobj.get("keyval", {}).get("public") == my_pub_hex:
            return kid
    raise RuntimeError("timestamp role 공개키가 root에 등록되어 있지 않습니다.")

def build_snapshot_meta_entry(snapshot_path: Optional[Path]) -> Dict[str, Any]:
    entry: Dict[str, Any] = {}
    if snapshot_path and snapshot_path.exists():
        blob = snapshot_path.read_bytes()
        sha = hashlib.sha256(blob).hexdigest()
        length = len(blob)
        try:
            snap = json.loads(blob)
            ver = int(snap.get("signed", {}).get("version", 1))
        except Exception:
            ver = 1
        entry["snapshot.json"] = {"hashes": {"sha256": sha}, "length": length, "version": ver}
    else:
        entry["snapshot.json"] = {"version": 1}
    return entry

def write_timestamp_json(version: int, doc: Dict[str, Any]) -> Path:
    out = DIRECTOR_METADATA_DIR / f"{version}.timestamp.json"
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return out

# ---------- 메인 ----------
def generate_timestamp() -> Path:
    """
    Timestamp 메타를 생성/서명하여 <version>.timestamp.json에 저장하고 Path를 반환.
    - 최신 root/snapshot 자동 탐색
    - 키/만료/경로는 .env/config로 관리
    - 서명 인코딩: base64
    """
    version = next_timestamp_version()

    # 1) keyid 해석 (root의 timestamp role에서 내 공개키 찾기)
    timestamp_pub_pem = DIRECTOR_KEYS_DIR / "timestamp_pub.pem"
    my_pub_hex = ed25519_pub_pem_to_raw_hex(timestamp_pub_pem)
    root_path = latest_root_path()
    timestamp_kid = resolve_timestamp_keyid_from_root_by_pubhex(root_path, my_pub_hex)

    # 2) snapshot 메타 항목 구성
    snap_path = latest_snapshot_path()
    meta = build_snapshot_meta_entry(snap_path)

    # 3) signed(timestamp) 작성
    signed_obj: Dict[str, Any] = {
        "_type": "timestamp",
        "expires": iso_utc_after_days(TIMESTAMP_EXPIRES_DAYS),
        "meta": meta,
        "spec_version": SPEC_VERSION,
        "version": version,
    }

    # 4) 서명(base64)
    sk = load_private_key(DIRECTOR_KEYS_DIR / "timestamp.pem")
    sig_b64 = ed25519_sign_b64(sk, canonical_json_bytes(signed_obj))

    result: Dict[str, Any] = {
        "signatures": [{"keyid": timestamp_kid, "sig": sig_b64}],
        "signed": signed_obj,
    }

    # 5) 저장 & Path 반환
    return write_timestamp_json(version, result)
