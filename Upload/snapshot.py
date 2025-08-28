#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Uptane/TUF snapshot 메타데이터 생성 + 서명 스크립트 (targets.json 존재 가정)
- meta.targets.json의 version 값을 실제 targets.json에서 읽어 반영
- Ed25519 공개키는 PEM -> RAW 32바이트 -> hex로 keyid 계산 (keys에는 포함되지 않지만 keyid 산출용)
- 서명은 Ed25519 개인키(snapshot.pem)로 수행, signatures 배열에 (keyid, sig hex) 추가
- expires: 한국 시간(now KST) + 7일 → UTC 'Z' 포맷
- 'signed' 필드 순서: _type → expires → meta → spec_version → version
"""

import json
import hashlib
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from zoneinfo import ZoneInfo
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ===== 설정 =====
SPEC_VERSION = "1.0.0"
VERSION = 1

SNAPSHOT_PUB_PEM = "snapshot_pub.pem"   # Ed25519 공개키(PEM)
SNAPSHOT_PRIV_PEM = "snapshot.pem"      # Ed25519 개인키(PEM)

TARGETS_JSON_PATH = "targets.json"      # 이미 존재한다고 가정
# 필요 시 "1.targets.json" 같은 버전 파일명을 지정하셔도 됩니다.
# 이 경우 아래에서 파일명의 베이스만 메타 키로 사용하시려면:
# META_KEY_NAME = os.path.basename(TARGETS_JSON_PATH)
META_KEY_NAME = "targets.json"

# ===== 유틸 =====
def canonical_json(obj) -> bytes:
    """서명용 canonical JSON(키 정렬 + 공백 최소화)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def tuf_keyid(keyobj: dict) -> str:
    """keyid = sha256(canonical_json(keyobj)) → hex"""
    return hashlib.sha256(canonical_json(keyobj)).hexdigest()

def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()

def ed25519_pem_to_raw_hex(pem_public: str) -> str:
    """Ed25519 공개키 PEM → raw 32바이트 → hex 문자열."""
    pub = serialization.load_pem_public_key(pem_public.encode("utf-8"), backend=default_backend())
    if not isinstance(pub, ed25519.Ed25519PublicKey):
        raise ValueError("제공된 PEM이 Ed25519 공개키가 아닙니다.")
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw.hex()

def load_ed25519_private(path: str, password: Optional[bytes] = None) -> ed25519.Ed25519PrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password, backend=default_backend())

def make_expires_iso8601_kst_plus_days(days: int) -> str:
    """현재 KST 기준 + days → UTC 'Z' ISO8601 문자열."""
    now_kst = datetime.now(ZoneInfo("Asia/Seoul"))
    exp_kst = now_kst + timedelta(days=days)
    return exp_kst.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def make_ed25519_keyentry_hex(hex_public: str) -> dict:
    """Ed25519 공개키(32B hex)를 TUF keys 항목 형태와 동일한 구조로 래핑 (keyid 계산용)."""
    return {
        "keytype": "ed25519",
        "scheme": "ed25519",
        "keyid_hash_algorithms": ["sha256", "sha512"],
        "keyval": {"public": hex_public},
    }

def read_targets_version(path: str) -> int:
    """targets.json에서 signed.version 값을 읽습니다. 기본값은 1."""
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    try:
        return int(doc["signed"]["version"])
    except Exception:
        return 1

# ===== 메인 =====
def generate_snapshot():
    # 1) snapshot 공개키 로드 → 32B hex → keyid 계산 (signatures용)
    snapshot_pub_pem = read_text(SNAPSHOT_PUB_PEM)
    snapshot_pub_hex = ed25519_pem_to_raw_hex(snapshot_pub_pem)
    snapshot_keyobj = make_ed25519_keyentry_hex(snapshot_pub_hex)
    snapshot_kid = tuf_keyid(snapshot_keyobj)

    # 2) targets.json의 version 읽기
    targets_ver = read_targets_version(TARGETS_JSON_PATH)

    # 3) snapshot signed payload (필드 순서 고정)
    expires = make_expires_iso8601_kst_plus_days(7)  # KST 기준 + 7일
    meta = {
        META_KEY_NAME: {"version": targets_ver}
    }
    snapshot_signed = {
        "_type": "snapshot",
        "expires": expires,
        "meta": meta,
        "spec_version": SPEC_VERSION,
        "version": VERSION,
    }

    # 4) canonicalize for signing
    to_be_signed = canonical_json(snapshot_signed)

    # 5) Ed25519 서명 생성
    priv = load_ed25519_private(SNAPSHOT_PRIV_PEM, password=None)
    sig_hex = priv.sign(to_be_signed).hex()

    # 6) signatures 배열 구성 (keyid는 snapshot 공개키의 keyid)
    signatures = [{"keyid": snapshot_kid, "sig": sig_hex}]

    # 7) 최종 문서 (출력 시 키 순서 유지)
    doc = {"signatures": signatures, "signed": snapshot_signed}

    outpath = f"{VERSION}.snapshot.json"
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False, sort_keys=False)
        f.write("\n")

    print(f"[ok] wrote {outpath}")
    print(f"[info] snapshot keyid: {snapshot_kid}")
    print(f"[info] targets.json version: {targets_ver}")
    print(f"[info] expires (UTC): {expires}")
