#!/usr/bin/env python3
# sign_targets_uptane.py (No argparse version)
# Always runs in AUTO MODE
# - 입력: ./data/inputs.txt 또는 ./data/targets/ 폴더
# - 출력: ./out/targets.json
# - 키:   ./keys/ed25519_priv.pem
# - 만료: 오늘 + 180일

import os, sys, json, hashlib, binascii, glob
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Tuple, Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

SPEC_VERSION = "1.0.0"

# 기본 경로
INPUT_LIST_FILE = "./data/inputs.txt"
INPUT_DIR = "./data/targets"
FALLBACK_DIR = "./data"
OUT_PATH = "./out/targets.json"
PRIVATE_KEY = "./keys/ed25519_priv.pem"
EXPIRES_DAYS = 180

def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def file_hashes_and_length(path: str) -> Tuple[Dict[str, str], int]:
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    total = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            total += len(chunk)
            sha256.update(chunk)
            sha512.update(chunk)
    return {"sha256": sha256.hexdigest(), "sha512": sha512.hexdigest()}, total

def ensure_key(priv_path: str) -> Ed25519PrivateKey:
    if os.path.exists(priv_path):
        with open(priv_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    # 없으면 생성
    sk = Ed25519PrivateKey.generate()
    pem = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    os.makedirs(os.path.dirname(priv_path) or ".", exist_ok=True)
    with open(priv_path, "wb") as f:
        f.write(pem)
    print(f"[i] generated new Ed25519 key: {priv_path}")
    return sk

def keyid_from_private(sk: Ed25519PrivateKey) -> str:
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return hashlib.sha256(pub).hexdigest()

def ed25519_sign_hex(sk: Ed25519PrivateKey, data: bytes) -> str:
    return binascii.hexlify(sk.sign(data)).decode("ascii")

def auto_pick_inputs() -> List[str]:
    if os.path.isfile(INPUT_LIST_FILE):
        with open(INPUT_LIST_FILE, "r", encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

    def list_files(d: str) -> List[str]:
        if not os.path.isdir(d): return []
        files = []
        for p in glob.glob(os.path.join(d, "*")):
            if os.path.isfile(p) and not p.endswith((".json",".sig",".sha256",".sha512",".tmp",".part",".swp")):
                files.append(p)
        return sorted(files)

    files = list_files(INPUT_DIR)
    return files if files else list_files(FALLBACK_DIR)

def auto_next_version() -> int:
    try:
        if os.path.isfile(OUT_PATH):
            with open(OUT_PATH, "r", encoding="utf-8") as f:
                doc = json.load(f)
            v = doc.get("signed", {}).get("version") or doc.get("version")
            if isinstance(v, int): return v + 1
    except: pass
    return 1

def iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")

def build_targets(inputs: List[str], version: int, expires: str) -> Dict[str,Any]:
    targets = {}
    for entry in inputs:
        path = entry.split(":",1)[0]
        tname = entry.split(":",1)[1] if ":" in entry else os.path.basename(path)
        if not os.path.isfile(path): continue
        hashes,length = file_hashes_and_length(path)
        targets[tname] = {"hashes": hashes, "length": length}
    return {
        "_type": "targets",
        "spec_version": SPEC_VERSION,
        "version": version,
        "expires": expires,
        "targets": targets
    }

def main():
    os.makedirs(os.path.dirname(OUT_PATH) or ".", exist_ok=True)
    inputs = auto_pick_inputs()
    if not inputs:
        print("[!] No input files found.")
        sys.exit(1)

    version = auto_next_version()
    expires = iso_utc(datetime.now(timezone.utc) + timedelta(days=EXPIRES_DAYS))
    sk = ensure_key(PRIVATE_KEY)
    keyid = keyid_from_private(sk)

    signed_obj = build_targets(inputs, version, expires)
    payload = canonical_json_bytes(signed_obj)
    sig_hex = ed25519_sign_hex(sk, payload)

    result = {"signatures":[{"keyid":keyid,"sig":sig_hex}], "signed":signed_obj}
    with open(OUT_PATH,"w",encoding="utf-8") as f:
        json.dump(result,f,ensure_ascii=False,indent=2,sort_keys=True)

    print(f"[ok] wrote {OUT_PATH}")
    print(f" keyid={keyid}, version={version}, expires={expires}")

if __name__=="__main__":
    main()
