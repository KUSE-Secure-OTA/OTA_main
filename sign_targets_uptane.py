#!/usr/bin/env python3
# sign_targets_uptane.py
# Build & sign targets.json (Uptane/TUF style)
# - single key, threshold=1
# - Ed25519 sig as HEX
# - spec_version=1.0.0, version=1 (default)

import argparse, json, os, sys, hashlib, binascii
from typing import Dict, Any, List, Tuple, Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

SPEC_VERSION = "1.0.0"

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
        # "local_path[:target_name]" �뺤떇
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

def main():
    ap = argparse.ArgumentParser(description="Build & sign targets.json (Uptane/TUF style)")
    ap.add_argument("-i", "--input", nargs="+", required=True, help="Files: local_path[:target_name]")
    ap.add_argument("-o", "--out", default="./out/targets.json", help="Output JSON path")
    ap.add_argument("--version", type=int, default=1, help="targets.json version (default 1)")
    ap.add_argument("--expires", default="2030-01-01T00:00:00Z", help='Expires ISO8601 UTC (e.g. "2030-01-01T00:00:00Z")')
    ap.add_argument("--delegations", help="Optional delegations JSON file")
    ap.add_argument("--private-key", default="./keys/ed25519_priv.pem", help="Ed25519 private key (PEM)")
    ap.add_argument("--autogen", action="store_true", help="Generate key if missing")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    sk = ensure_key(args.private_key, args.autogen)
    keyid = keyid_from_private(sk)

    deleg = None
    if args.delegations:
        with open(args.delegations, "r", encoding="utf-8") as f:
            deleg = json.load(f)

    signed_obj = build_targets_obj(args.input, args.version, args.expires, deleg)
    payload = canonical_json_bytes(signed_obj)
    sig_hex = ed25519_sign_hex(sk, payload)

    result = {"signatures": [{"keyid": keyid, "sig": sig_hex}], "signed": signed_obj}

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2, sort_keys=True)

    print(f"[ok] wrote {args.out}")
    print(f"[i] keyid={keyid}, version={args.version}, expires={args.expires}")

if __name__ == "__main__":
    main()