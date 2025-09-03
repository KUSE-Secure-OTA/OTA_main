from __future__ import annotations
import json, re, time, base64, os
from typing import Dict, Any, List, Optional, Tuple

# ====== 설정(임시) ==========================================
DIRECTOR_SIGN_KEY_PATH = "./keys/director_targets_priv.pem"   # Ed25519 개인키(PEM) 경로
DIRECTOR_SIGN_KEYID    = "director_targets_keyid"             # 서명 keyid 표기
SPEC_VERSION           = "1.0.0"                              # Uptane/TUF spec 버전(팀 규칙대로)
EXPIRES_TTL_SEC        = 24 * 3600                            # 만료 24h (원하시면 조정)

# ====== 파일명 파싱 & 버전 비교 =============================
# 파일명 규칙: name.version.ext  (예: engine_control.2.1.bin)
_RX_DOT = re.compile(r'^(?P<name>.+?)\.(?P<ver>\d+(?:\.\d+)*)\.(?P<ext>[^.]+)$')

def parse_name_version(filename: str) -> Optional[Tuple[str, str, str]]:
    m = _RX_DOT.match(filename)
    if not m:
        return None
    return m.group('name'), m.group('ver'), '.' + m.group('ext')

# 고정 자리수 가정: "a.b.c" → 정수 리스트로 단순 비교(패딩 없음)
def _split_ver_fixed(ver: str) -> List[int]:
    return [int(x) for x in ver.split('.')]

def version_gt(a: str, b: str) -> bool:
    return _split_ver_fixed(a) > _split_ver_fixed(b)

# ====== VVM → 설치 목록(다건) 추출 ==========================
# 반환: [(ecu_serial, filename, version, fileinfo), ...]
def extract_installed_list_from_vvm(vvm_raw: Dict[str, Any]) -> List[Tuple[str, str, str, Dict[str, Any]]]:
    out: List[Tuple[str, str, str, Dict[str, Any]]] = []
    body = vvm_raw.get("signed", vvm_raw)
    evrs = body.get("ecu_version_reports", []) or []
    for evr in evrs:
        s = (evr or {}).get("signed", {}) or {}
        ecu_id = s.get("ecu_serial") or ""
        installed = s.get("installed_image") or {}
        if not isinstance(installed, dict) or not installed:
            continue
        # {"engine_control.2.1.bin": {...}} → 첫(유일) 항목 사용
        filename, fileinfo = next(iter(installed.items()))
        pv = parse_name_version(filename)
        if not pv:
            continue
        _, ver, _ = pv
        out.append((ecu_id, filename, ver, fileinfo))
    return out

# ====== targets에서 동일 "이름(name)"의 최신(=유일) 항목 찾기 =====
# 전제: targets.json에는 해당 name의 "최신 1개"만 존재
def find_latest_in_targets_by_name(global_targets: Dict[str, Any], base_name: str) -> Optional[Tuple[str, Dict[str, Any], str]]:
    all_targets = (global_targets.get("signed") or {}).get("targets") or {}
    for fname, meta in all_targets.items():
        pv = parse_name_version(fname)
        if not pv:
            continue
        name, ver, _ = pv
        if name == base_name:
            return fname, meta, ver
    return None

# ====== Canonical JSON (서명 바이트 고정) ===================
def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

# ====== Ed25519 서명 (cryptography 사용) ====================
def _sign_ed25519_pem(message: bytes, pem_path: str) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    with open(pem_path, "rb") as f:
        key_data = f.read()
    sk = serialization.load_pem_private_key(key_data, password=None)
    if not isinstance(sk, Ed25519PrivateKey):
        raise TypeError("Expected Ed25519 private key in PEM")
    sig = sk.sign(message)
    return base64.b64encode(sig).decode("ascii")

# ====== 메인: VVM/targets 비교 → 최종 targets_car(서명 포함) 생성 ===
def select_and_build_targets_car(vvm_raw: Dict[str, Any],
                                 global_targets: Dict[str, Any]) -> Dict[str, Any]:
    # 1) 설치 목록 추출(ECU 다건)
    installed_list = extract_installed_list_from_vvm(vvm_raw)

    # 2) 업데이트 대상 선별
    selected: Dict[str, Any] = {}
    any_update = False

    for ecu_id, installed_fname, installed_ver, installed_fileinfo in installed_list:
        parsed = parse_name_version(installed_fname)
        if not parsed:
            continue
        base_name, _, _ = parsed

        found = find_latest_in_targets_by_name(global_targets, base_name)
        if not found:
            # targets에 해당 name이 없으면 스킵(정책상 update=False로 간주)
            continue

        latest_fname, latest_meta, latest_ver = found

        # targets(최신) > 설치버전 ?
        try:
            need_update = version_gt(latest_ver, installed_ver)
        except Exception:
            # 포맷 이슈 시 해시 비교 보조
            best_sha = (latest_meta.get("hashes") or {}).get("sha256")
            cur_sha  = (installed_fileinfo.get("hashes") or {}).get("sha256")
            need_update = bool(best_sha and cur_sha and best_sha != cur_sha)

        if need_update:
            any_update = True
            selected[latest_fname] = latest_meta

    # 3) 최종 signed 블록 구성 (여기서 version/expires도 채움)
    expires_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + EXPIRES_TTL_SEC))

    final_signed = {
        "_type": "targets",
        "spec_version": SPEC_VERSION,
        "version": 1,               # version 증가하도록 수정 필요.
        "expires": expires_str,
        "targets": selected,
        "update": bool(any_update)
    }

    # 4) Director 키로 서명
    if not os.path.exists(DIRECTOR_SIGN_KEY_PATH):
        raise FileNotFoundError(f"Director signing key not found: {DIRECTOR_SIGN_KEY_PATH}")

    msg = canonical_json_bytes(final_signed)
    sig_b64 = _sign_ed25519_pem(msg, DIRECTOR_SIGN_KEY_PATH)

    final_doc = {
        "signatures": [
            {"keyid": DIRECTOR_SIGN_KEYID, "sig": sig_b64}
        ],
        "signed": final_signed
    }

    # 디버그(선택)
    debug = {
        "installed_count": len(installed_list),
        "selected_count": len(selected),
        "update": any_update
    }
    return {"targets_doc": final_doc, "debug": debug}
