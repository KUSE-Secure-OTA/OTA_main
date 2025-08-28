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

SPEC_VERSION = "1.0.0"

# ===== 사용자 정의 기본값 =====
DEFAULT_INPUTS   = ["temp.bin"]   # 입력 파일 (local_path[:target_name])
DEFAULT_OUT      = "./metadata/targets.json"                     # 출력 JSON 파일
DEFAULT_VERSION  = 1
DEFAULT_EXPIRES  = "2030-01-01T00:00:00Z"
DEFAULT_DELEG    = None
DEFAULT_PRIVKEY  = "targets.pem"

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

def keyid_from_private(sk: Ed25519PrivateKey) -> str:
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return hashlib.sha256(pub).hexdigest()

def ed25519_sign_hex(sk: Ed25519PrivateKey, data: bytes) -> str:
    sig = sk.sign(data)
    return binascii.hexlify(sig).decode("ascii")

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
) -> Dict[str, Any]:
    """
    Build & sign targets metadata.

    - inputs: ["local_path[:target_name]", ...]
    - out_path: 결과 JSON 경로 (예: "./metadata/targets.json")
    - version: 정수 버전
    - expires: ISO8601 UTC ("YYYY-MM-DDTHH:MM:SSZ")
    - delegations: 선택
    - privkey_path: Ed25519 개인키(PEM) 경로
    """
    # 출력 디렉터리 보장
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    # 키 로드 및 keyid 산출
    sk = load_private_key_or_exit(privkey_path)
    keyid = keyid_from_private(sk)

    # signed 객체 구성
    signed_obj = build_targets_obj(inputs, int(version), expires, delegations)

    # 서명
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
