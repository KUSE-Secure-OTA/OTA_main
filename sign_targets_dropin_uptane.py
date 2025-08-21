#!/usr/bin/env python3
# sign_targets_uptane.py
# Build & sign targets.json (Uptane/TUF style)
# - single key, threshold=1
# - Ed25519 sig as HEX
# - spec_version=1.0.0, version=1 (default)

import argparse, json, os, sys, hashlib, binascii
from typing import Dict, Any, List, Tuple, Optional, Union
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

SPEC_VERSION = "1.0.0"

def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def file_hashes_and_length(path: str) -> Tuple[Dict[str, str], int]:
    import hashlib
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    total = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            if not chunk:
                break
            total += len(chunk)
            sha256.update(chunk)
            sha512.update(chunk)
    return {"sha256": sha256.hexdigest(), "sha512": sha512.hexdigest()}, total

def ensure_key(priv_path: str, autogen: bool) -> Ed25519PrivateKey:
    if os.path.exists(priv_path):
        with open(priv_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    if not autogen:
        print(f"[!] Private key not found: {priv_path}. Use --autogen or provide one.", file=sys.stderr)
        sys.exit(2)
    sk = Ed25519PrivateKey.generate()
    pem = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    os.makedirs(os.path.dirname(priv_path) or ".", exist_ok=True)
    with open(priv_path, "wb") as f:
        f.write(pem)
    return sk

def keyid_from_private(sk: Ed25519PrivateKey) -> str:
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return hashlib.sha256(pub).hexdigest()

def ed25519_sign_hex(sk: Ed25519PrivateKey, data: bytes) -> str:
    sig = sk.sign(data)  # 64 bytes
    return binascii.hexlify(sig).decode("ascii")

def build_targets_obj(inputs: List[str], version: int, expires: str, delegations: Optional[Dict[str,Any]]) -> Dict[str,Any]:
    targets: Dict[str, Any] = {}
    for entry in inputs:
        # "local_path[:target_name]" 형식
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

def coerce_to_signed_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    유연하게 입력을 받아 '서명대상(signed)' 블록을 리턴:
    - 이미 {"signed": {...}, "signatures": [...]} 형태면 그대로 사용
    - 상단이 바로 targets 오브젝트면 {"signed": obj, "signatures": []} 로 감쌈
    """
    if "signed" in doc and isinstance(doc["signed"], dict):
        # signatures는 새로 덮어씀(재서명/초기서명 모두 동일경로)
        out = {"signed": doc["signed"], "signatures": []}
        return out
    else:
        # unsigned 형태로 보고 래핑
        return {"signed": doc, "signatures": []}

def maybe_override_meta(signed_obj: Dict[str, Any], version: Optional[int], expires: Optional[str]) -> None:
    if version is not None:
        signed_obj["version"] = int(version)
    if expires:
        signed_obj["expires"] = expires
    # 필드 보강(호환용)
    signed_obj.setdefault("_type", "targets")
    signed_obj.setdefault("spec_version", SPEC_VERSION)
    signed_obj.setdefault("targets", {})

def main():
    ap = argparse.ArgumentParser(description="Build & sign targets.json (Uptane/TUF style)")
    mx = ap.add_mutually_exclusive_group(required=True)
    mx.add_argument("-i", "--input", nargs="+", help="Files: local_path[:target_name]")
    mx.add_argument("--json-in", help="Sign-only mode: unsigned targets doc path (or full doc with 'signed')")
    ap.add_argument("-o", "--out", default="./out/targets.json", help="Output JSON path")
    ap.add_argument("--version", type=int, help="targets.json version (override when used with --json-in; default 1 in build mode)")
    ap.add_argument("--expires", help='Expires ISO8601 UTC (override when used with --json-in; e.g. "2030-01-01T00:00:00Z")')
    ap.add_argument("--delegations", help="Optional delegations JSON file (build mode only)")
    ap.add_argument("--private-key", default="./keys/ed25519_priv.pem", help="Ed25519 private key (PEM)")
    ap.add_argument("--autogen", action="store_true", help="Generate key if missing")
    # build-mode 기본값(기존과 동작 유지)
    ap.set_defaults(version=1, expires="2030-01-01T00:00:00Z")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    sk = ensure_key(args.private_key, args.autogen)
    keyid = keyid_from_private(sk)

    # 1) BUILD MODE (기존 동작)
    if args.input:
        deleg = None
        if args.delegations:
            with open(args.delegations, "r", encoding="utf-8") as f:
                deleg = json.load(f)
        signed_obj = build_targets_obj(args.input, args.version, args.expires, deleg)

    # 2) SIGN-ONLY MODE (새로 추가) — director_selector 출력과 연동
    else:
        with open(args.json_in, "r", encoding="utf-8") as f:
            raw = json.load(f)
        wrapper = coerce_to_signed_doc(raw)
        signed_obj = wrapper["signed"]
        # 필요 시 version/expires 덮어쓰기(없으면 원문 유지)
        maybe_override_meta(signed_obj,
                            version=args.version if args.version is not None else None,
                            expires=args.expires)

    # canonicalize & sign
    payload = canonical_json_bytes(signed_obj)
    sig_hex = ed25519_sign_hex(sk, payload)
    result = {"signatures": [{"keyid": keyid, "sig": sig_hex}], "signed": signed_obj}

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2, sort_keys=True)

    # 로그
    print(f"[ok] wrote {args.out}")
    print(f"[i] keyid={keyid}, version={signed_obj.get('version')}, expires={signed_obj.get('expires')}")

if __name__ == "__main__":
    main()
