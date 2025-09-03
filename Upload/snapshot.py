import json, os, re, binascii
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ===== 설정 =====
SPEC_VERSION = "1.0.0"
VERSION = 1

SNAPSHOT_PRIV_PEM     = "snapshot.pem"        # Ed25519 개인키(PEM)
SNAPSHOT_PUB_PEM      = "snapshot_pub.pem"    # Ed25519 공개키(PEM)
ROOT_JSON_PATH        = "1.root.json"         # 참조할 root 메타데이터
TARGETS_JSON_PATH     = "targets.json"        # 파일명은 1.targets.json이어도 meta 키는 "targets.json"
DEFAULT_EXPIRES_DAYS  = 7                     # KST 기준 + 7일
OUTPUT_DIR            = "."                   # 스냅샷 파일( N.snapshot.json ) 저장 디렉터리

# ===== 유틸 =====
def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def load_private_key_or_exit(path: str) -> Ed25519PrivateKey:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Private key not found: {path}")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def ed25519_sign_hex(sk: Ed25519PrivateKey, data: bytes) -> str:
    sig = sk.sign(data)
    return binascii.hexlify(sig).decode("ascii")

def ed25519_pem_to_raw_hex_from_file(pub_pem_path: str) -> str:
    """공개키 PEM → RAW 32바이트 → hex 문자열."""
    if not os.path.exists(pub_pem_path):
        raise FileNotFoundError(f"Public key not found: {pub_pem_path}")
    with open(pub_pem_path, "r", encoding="utf-8") as f:
        pem = f.read().strip()
    pub = serialization.load_pem_public_key(pem.encode("utf-8"), backend=default_backend())
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)  # 32 bytes
    return raw.hex()

def make_expires_iso8601_kst_plus_days(days: int) -> str:
    """현재 KST 기준 + days → UTC 'Z' ISO8601."""
    now_kst = datetime.now(ZoneInfo("Asia/Seoul"))
    exp_kst = now_kst + timedelta(days=days)
    return exp_kst.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def read_targets_version(path: str) -> int:
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    try:
        return int(doc["signed"]["version"])
    except Exception:
        return 1

def resolve_snapshot_keyid_from_root_by_pubhex(root_path: str, my_pub_hex: str) -> str:
    """
    root.json의 roles.snapshot.keyids 목록만 순회.
    각 keyid에 대해 signed.keys[keyid].keyval.public 과 my_pub_hex를 비교.
    일치하는 keyid를 반환. 없으면 예외.
    """
    if not os.path.exists(root_path):
        raise FileNotFoundError(f"root.json not found: {root_path}")
    with open(root_path, "r", encoding="utf-8") as f:
        root_doc = json.load(f)

    signed = root_doc["signed"]
    keys = signed["keys"]                           # { keyid: keyobj }
    role_kids = signed["roles"]["snapshot"]["keyids"]  # [ keyid, ... ]

    for kid in role_kids:
        keyobj = keys[kid]
        if keyobj.get("keytype") == "ed25519" and keyobj.get("keyval", {}).get("public") == my_pub_hex:
            return kid

    raise RuntimeError("[!] root.json의 'snapshot' role에 공개키가 등록되어 있지 않습니다.")

# ===== 메인 =====
def generate_snapshot() -> Dict[str, Any]:
    version = VERSION

     # 1) 내 공개키(hex) → root로부터 정확한 keyid 선택
    my_pub_hex = ed25519_pem_to_raw_hex_from_file(SNAPSHOT_PUB_PEM)
    snapshot_kid = resolve_snapshot_keyid_from_root_by_pubhex(ROOT_JSON_PATH, my_pub_hex)

    # 2) targets 버전 & meta 키 이름("targets.json") 결정
    targets_ver = read_targets_version(TARGETS_JSON_PATH)
    meta_key = "targets.json"  # 메타데이터 내부에서의 표준 키 이름 (파일 저장명이 1.targets.json이어도 고정)

    # 3) signed(snapshot) 구성
    expires = make_expires_iso8601_kst_plus_days(EXPIRES_DAYS_KST)
    meta_entry: Dict[str, Any] = {"version": targets_ver}
    snapshot_signed: Dict[str, Any] = {
        "_type": "snapshot",
        "expires": expires,
        "meta": {meta_key: meta_entry},
        "spec_version": SPEC_VERSION,
        "version": int(version),
    }

    # 4) 서명
    payload = canonical_json_bytes(snapshot_signed)
    sk = load_private_key_or_exit(SNAPSHOT_PRIV_PEM)
    sig_hex = ed25519_sign_hex(sk, payload)

    # 5) 결과
    result: Dict[str, Any] = {
        "signatures": [{"keyid": snapshot_kid, "sig": sig_hex}],
        "signed": snapshot_signed,
    }

    os.makedirs(OUTPUT_DIR or ".", exist_ok=True)
    outpath = os.path.join(OUTPUT_DIR, f"{int(version)}.snapshot.json")
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=1, sort_keys=False)
        f.write("\n")

    print(f"[ok] wrote {outpath}")
    return result
