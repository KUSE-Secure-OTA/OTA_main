#!/usr/bin/env python3
# sign_timestamp_uptane.py
# Build & sign timestamp.json (Uptane/TUF style)
# - single key, threshold=1
# - Ed25519 sig as HEX
# - spec_version=1.0.0, version=1
# - expires = generated_at + 24h (怨좎젙)
# - custom.generated_at / custom.expiry_ttl_hours 異붽�

import argparse, json, os, sys, hashlib, binascii, datetime
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

SPEC_VERSION = "1.0.0"

def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

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
    sig = sk.sign(data)
    return binascii.hexlify(sig).decode("ascii")

def load_snapshot_meta(snapshot_path: Optional[str], fallback_version: int = 1) -> Dict[str,Any]:
    meta: Dict[str,Any] = {}
    if snapshot_path and os.path.exists(snapshot_path):
        with open(snapshot_path, "rb") as f:
            blob = f.read()
        sha256 = hashlib.sha256(blob).hexdigest()
        length = len(blob)
        try:
            snap = json.loads(blob)
            ver = int(snap.get("signed", {}).get("version", fallback_version))
        except Exception:
            ver = fallback_version
        meta["snapshot.json"] = {"hashes": {"sha256": sha256}, "length": length, "version": ver}
    else:
        meta["snapshot.json"] = {"version": int(fallback_version)}
    return meta

def now_utc_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def add_hours(iso_now: str, hours: int) -> str:
    dt = datetime.datetime.fromisoformat(iso_now.replace("Z",""))
    return (dt + datetime.timedelta(hours=hours)).isoformat() + "Z"

def main():
    ap = argparse.ArgumentParser(description="Build & sign timestamp.json (Uptane/TUF style, 24h expiry)")
    ap.add_argument("--snapshot", default="./out/snapshot.json", help="Path to snapshot.json (optional)")
    ap.add_argument("-o", "--out", default="./out/timestamp.json", help="Output JSON path")
    ap.add_argument("--version", type=int, default=1, help="timestamp.json version (default 1)")
    ap.add_argument("--private-key", default="./keys/ed25519_priv.pem", help="Ed25519 private key (PEM)")
    ap.add_argument("--autogen", action="store_true", help="Generate key if missing")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    issued_iso = now_utc_iso()
    expires_iso = add_hours(issued_iso, 24)

    sk = ensure_key(args.private_key, args.autogen)
    keyid = keyid_from_private(sk)

    signed_obj = {
        "_type": "timestamp",
        "spec_version": SPEC_VERSION,
        "version": int(args.version),
        "expires": expires_iso,
        "meta": load_snapshot_meta(args.snapshot, fallback_version=1),
        "custom": {
            "generated_at": issued_iso,
            "expiry_ttl_hours": 24
        }
    }

    payload = canonical_json_bytes(signed_obj)
    sig_hex = ed25519_sign_hex(sk, payload)

    result = {"signatures": [{"keyid": keyid, "sig": sig_hex}], "signed": signed_obj}

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2, sort_keys=True)

    print(f"[ok] wrote {args.out}")
    print(f"[i] generated_at={issued_iso}")
    print(f"[i] expires_at={expires_iso} (fixed 24h TTL)")
    print(f"[i] keyid={keyid}, version={args.version}")

if __name__ == "__main__":
    main()