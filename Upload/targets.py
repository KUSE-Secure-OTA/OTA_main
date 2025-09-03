#!/usr/bin/env python3
# sign_targets_uptane.py
# Build & sign targets.json (Uptane/TUF style)
# - single key, threshold=1
# - Ed25519 sig as HEX
# - spec_version=1.0.0, version=1 (default)

import json, os, sys, hashlib, binascii
from typing import Dict, Any, List, Tuple, Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SPEC_VERSION = "1.0.0"

# ===== 사용자 정의 기본값 =====
DEFAULT_INPUTS   = ["temp.bin"]   # 입력 파일 (local_path[:target_name])
DEFAULT_OUT      = "./metadata/targets.json"                     # 출력 JSON 파일
DEFAULT_VERSION  = 1
DEFAULT_EXPIRES  = "2030-01-01T00:00:00Z"
DEFAULT_DELEG    = None
DEFAULT_PRIVKEY  = "targets.pem"
DEFAULT_TARGETS_PUB= "targets_pub.pem"
DEFAULT_ROOTPATH = "1.root.json"  # keyid 참조할 root

def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def file_hashes_and_length(path: str) -> Tuple[Dict[str, str], int]:
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    total = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            if not chunk: break
            total += len(chunk)
            sha256.update(chunk)
            sha512.update(chunk)
    return {"sha256": sha256.hexdigest(), "sha512": sha512.hexdigest()}, total

def load_private_key_or_exit(priv_path: str) -> Ed25519PrivateKey:
    if not os.path.exists(priv_path):
        print(f"[!] Private key not found: {priv_path}.", file=sys.stderr)
        sys.exit(2)
    try:
        with open(priv_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except Exception as e:
        print(f"[!] Failed to load private key: {e}", file=sys.stderr)
        sys.exit(2)

def ed25519_sign_hex(sk: Ed25519PrivateKey, data: bytes) -> str:
    sig = sk.sign(data)
    return binascii.hexlify(sig).decode("ascii")

def ed25519_pem_to_raw_hex_from_file(pub_pem_path: str) -> str:
    if not os.path.exists(pub_pem_path):
        print(f"[!] targets_pub.pem not found: {pub_pem_path}", file=sys.stderr)
        sys.exit(2)
    with open(pub_pem_path, "r", encoding="utf-8") as f:
        pem = f.read().strip()
    pub = serialization.load_pem_public_key(pem.encode("utf-8"), backend=default_backend())
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)  # 32 bytes
    return raw.hex()

def resolve_targets_keyid_from_root_by_pubhex(root_path: str, my_pub_hex: str) -> str:
    """
    root.json의 roles.targets.keyids 목록 순회.
    각 keyid에 대해 signed.keys[keyid].keyval.public 과 my_pub_hex를 비교.
    일치하는 keyid를 반환. 없으면 에러.
    """
    if not os.path.exists(root_path):
        print(f"[!] root.json not found: {root_path}", file=sys.stderr)
        sys.exit(2)
    with open(root_path, "r", encoding="utf-8") as f:
        root_doc = json.load(f)

    signed = root_doc["signed"]
    keys = signed["keys"]                       # {keyid: keyobj}
    role_kids = signed["roles"]["targets"]["keyids"]  # [keyid, ...]

    for kid in role_kids:
        keyobj = keys[kid]
        if keyobj.get("keytype") == "ed25519" and keyobj.get("keyval", {}).get("public") == my_pub_hex:
            return kid

    print("[!] root.json의 'targets' role에 공개키가 등록되어 있지 않습니다.", file=sys.stderr)
    sys.exit(3)

def build_targets_obj(inputs: List[str], version: int, expires: str, delegations: Optional[Dict[str,Any]]) -> Dict[str,Any]:
    targets: Dict[str, Any] = {}
    for entry in inputs:
        if ":" in entry:
            path, tname = entry.split(":", 1)
        else:
            path, tname = entry, os.path.basename(entry)
        hashes, length = file_hashes_and_length(path)
        targets[tname] = {"hashes": hashes, "length": length}
    obj: Dict[str, Any] = {
        "_type": "targets",
        "spec_version": SPEC_VERSION,
        "version": int(version),
        "expires": expires,
        "targets": targets
    }
    if delegations is not None:
        obj["delegations"] = delegations
    return obj

def make_targets(
    inputs: List[str] = DEFAULT_INPUTS,
    out_path: str = DEFAULT_OUT,
    version: int = DEFAULT_VERSION,
    expires: str = DEFAULT_EXPIRES,
    delegations: Optional[Dict[str, Any]] = DEFAULT_DELEG,
    privkey_path: str = DEFAULT_PRIVKEY,
    root_path: str = DEFAULT_ROOT_JSON,
    targets_pub_pem: str = DEFAULT_TARGETS_PUB,
) -> Dict[str, Any]:

    # 출력 디렉터리 보장
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    # root로부터 keyid 획득
    my_pub_hex = ed25519_pem_to_raw_hex_from_file(targets_pub_pem)
    keyid = resolve_targets_keyid_from_root_by_pubhex(root_path, my_pub_hex)

    # signed 객체 구성
    signed_obj = build_targets_obj(inputs, int(version), expires, delegations)

    # 서명
    sk = load_private_key_or_exit(privkey_path)
    payload = canonical_json_bytes(signed_obj)
    sig_hex = ed25519_sign_hex(sk, payload)

    # 결과 작성
    result: Dict[str, Any] = {
        "signatures": [{"keyid": keyid, "sig": sig_hex}],
        "signed": signed_obj,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2, sort_keys=True)

    print(f"[ok] wrote {out_path}")
    print(f"[i] keyid={keyid}, version={int(version)}, expires={expires}")
    return result
