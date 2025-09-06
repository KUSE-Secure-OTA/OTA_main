import json, os, re, binascii
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ===== 설정 =====
SPEC_VERSION          = "1.0.0"
META_DIR              = "./meta"
ROOT_JSON_PATH        = "./meta/1.root.json"         # 참조할 root 메타데이터
TARGETS_JSON_PATH     = "./targets.json"
DEFAULT_EXPIRES_DAYS  = 7

SNAPSHOT_PRIV_PEM     = "snapshot.pem"
SNAPSHOT_PUB_PEM      = "snapshot_pub.pem"

# ===== 유틸 =====
def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def load_private_key(path: str) -> Ed25519PrivateKey:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Private key not found: {path}")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def ed25519_sign_hex(sk: Ed25519PrivateKey, data: bytes) -> str:
    sig = sk.sign(data)
    return binascii.hexlify(sig).decode("ascii")

def ed25519_pub_pem_to_raw_hex(pub_pem_path: str) -> str:
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
    return int(doc["signed"]["version"])


def resolve_snapshot_keyid_from_root_by_pubhex(root_path: str, my_pub_hex: str) -> str:
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

def next_snapshot_version() -> int:
    latest = 0
    pat = re.compile(r"^(\d+)\.snapshot\.json$")
    if os.path.isdir(META_DIR):a
        for name in os.listdir(META_DIR):
            m = pat.match(name)
            if m:
                latest = max(latest, int(m.group(1)))
    return latest + 1

# ===== 메인 =====
def generate_snapshot() -> Dict[str, Any]:
    version = next_snapshot_version()

     # 1) 내 공개키(hex) → root로부터 정확한 keyid 선택
    my_pub_hex = ed25519_pub_pem_to_raw_hex(SNAPSHOT_PUB_PEM)
    snapshot_kid = resolve_snapshot_keyid_from_root_by_pubhex(ROOT_JSON_PATH, my_pub_hex)

    # 2) targets 버전 & meta 키 이름("targets.json") 결정
    targets_ver = read_targets_version(TARGETS_JSON_PATH)
    meta_key = "targets.json"

    # 3) signed(snapshot) 구성
    expires = make_expires_iso8601_kst_plus_days(EXPIRES_DAYS_KST)
    snapshot_signed: Dict[str, Any] = {
        "_type": "snapshot",
        "expires": expires,
        "meta": {meta_key: {"version": targets_ver}},
        "spec_version": SPEC_VERSION,
        "version": version,
    }

    # 4) 서명
    payload = canonical_json_bytes(snapshot_signed)
    sk = load_private_key(SNAPSHOT_PRIV_PEM)
    sig_hex = ed25519_sign_hex(sk, payload)

    # 5) 결과
    result: Dict[str, Any] = {
        "signatures": [{"keyid": snapshot_kid, "sig": sig_hex}],
        "signed": snapshot_signed,
    }

    return result
