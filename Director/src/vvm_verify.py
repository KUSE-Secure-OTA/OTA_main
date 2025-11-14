# Director/src/vvm_verify.py
from __future__ import annotations
import json, base64, binascii, logging
from pathlib import Path
from typing import Any, Dict, List, Tuple

from config import DIRECTOR_METADATA_DIR, DIRECTOR_KEYS_DIR
from src.targets_per_vehicle import canonical_json_bytes

log = logging.getLogger("vvm-verify")

def _find_root_vvm_path() -> Path:
    # 1순위: meta/root_vvm.json
    p_meta = (DIRECTOR_METADATA_DIR / "root_vvm.json").resolve()
    if p_meta.exists():
        return p_meta
    # 2순위: keys/root_vvm.json (폴백)
    p_keys = (DIRECTOR_METADATA_DIR / "root_vvm.json").resolve()
    if p_keys.exists():
        return p_keys
    # 둘 다 없으면 meta 경로 반환(이후 read 시 오류)
    return p_meta

def _load_root_vvm(path: Path | None = None) -> Dict[str, Any]:
    if path is None:
        path = _find_root_vvm_path()
    return json.loads(path.read_text(encoding="utf-8"))

def _get_vvm_keyinfo_map(root_doc: Dict[str, Any]) -> Dict[str, Tuple[str, Any, str]]:
    """
    roles.vvm.keyids에 등록된 공개키들을 dict로 수집
    반환: { keyid: (keytype, pubkey_obj_or_bytes, scheme) }
      - ed25519: ( "ed25519", public_bytes(32), "ed25519" )
      - rsa:     ( "rsa",     public_key_object, "rsassa-pss-sha256" )
    """
    from cryptography.hazmat.primitives import serialization
    signed = root_doc.get("signed", {})
    roles = signed.get("roles", {}) or {}
    vvm_role = roles.get("vvm", {}) or {}
    keyids: List[str] = vvm_role.get("keyids", []) or []
    keys = signed.get("keys", {}) or {}

    out: Dict[str, Tuple[str, Any, str]] = {}
    for kid in keyids:
        k = keys.get(kid) or {}
        ktype = (k.get("keytype") or "").lower()
        scheme = (k.get("scheme") or "").lower()
        kval = (k.get("keyval") or {}).get("public")

        if ktype == "ed25519" and isinstance(kval, str):
            try:
                pub = bytes.fromhex(kval)  # 32 bytes
                if len(pub) != 32:
                    raise ValueError("ed25519 public key must be 32 bytes")
                out[kid] = ("ed25519", pub, "ed25519")
            except (ValueError, binascii.Error):
                log.error(f"[root_vvm] invalid ed25519 public key hex for keyid={kid}")
        elif ktype == "rsa" and isinstance(kval, str) and kval.startswith("-----BEGIN"):
            try:
                pub = serialization.load_pem_public_key(kval.encode("utf-8"))
                # scheme 기대치 확인(권장)
                if scheme not in ("rsassa-pss-sha256", "rsassa-pss"):
                    log.warning(f"[root_vvm] rsa scheme not explicitly rsassa-pss-sha256 for keyid={kid}: {scheme}")
                out[kid] = ("rsa", pub, scheme or "rsassa-pss-sha256")
            except Exception as e:
                log.error(f"[root_vvm] failed to load RSA public key for keyid={kid}: {e}")
        else:
            log.warning(f"[root_vvm] unsupported key for vvm role: keyid={kid}, keytype={ktype}, scheme={scheme}")
    return out

def verify_vvm_signature(vvm_doc: Dict[str, Any], root_doc: Dict[str, Any] | None = None) -> bool:
    """
    VVM 최상위 서명 검증:
      - signature(s)[].keyid ∈ roles.vvm.keyids
      - keytype에 따라 ed25519 또는 RSA-PSS(SHA256)로 검증
      - 메시지 = canonical_json_bytes(vvm_doc["signed"])
      - threshold=1: 하나라도 통과하면 True
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519, padding as asy_padding
    from cryptography.hazmat.primitives import hashes

    # 1) 서명 배열
    sigs = vvm_doc.get("signature") or vvm_doc.get("signatures") or []
    if not isinstance(sigs, list) or not sigs:
        log.error("VVM has no signatures[]")
        return False

    # 2) signed 바디
    signed_body = vvm_doc.get("signed")
    if not isinstance(signed_body, dict):
        log.error("VVM 'signed' is not a dict")
        return False

    # 3) root_vvm 로드 및 vvm role 키 준비
    try:
        root_doc = root_doc or _load_root_vvm()
    except Exception as e:
        log.error(f"Failed to load root_vvm.json: {e}")
        return False

    keymap = _get_vvm_keyinfo_map(root_doc)
    if not keymap:
        log.error("No vvm keys found in root_vvm.json")
        return False

    # 4) canonical 메시지 생성
    message = canonical_json_bytes(signed_body)

    # 5) 각 서명 시도
    for s in sigs:
        keyid = s.get("keyid"); sig_b64 = s.get("sig")
        if not keyid or not sig_b64:
            log.error("VVM signature entry missing keyid or sig")
            continue

        entry = keymap.get(keyid)
        if not entry:
            log.error(f"VVM keyid not found in roles.vvm: {keyid}")
            continue

        try:
            sig = base64.b64decode(sig_b64)
        except Exception as e:
            log.error(f"base64 decode failed for keyid={keyid}: {e}")
            continue

        ktype, pub, scheme = entry
        try:
            if ktype == "ed25519":
                ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
                log.info(f"VVM signature OK (ed25519, keyid={keyid})")
                return True
            elif ktype == "rsa":
                # 기본 정책: RSA-PSS + SHA256
                pub.verify(
                    sig, message,
                    asy_padding.PSS(
                        mgf=asy_padding.MGF1(hashes.SHA256()),
                        salt_length=asy_padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                log.info(f"VVM signature OK (RSA-PSS, keyid={keyid})")
                return True
            else:
                log.error(f"Unsupported keytype for keyid={keyid}: {ktype}")
        except Exception as e:
            log.error(f"Signature verify failed for keyid={keyid}: {e}")
            continue

    log.error("No signature matched any allowed vvm key")
    return False
