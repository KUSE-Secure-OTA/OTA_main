# Director/src/targets_per_vehicle.py
import json, os, re, binascii
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from config import DIRECTOR_KEYS_DIR, DIRECTOR_METADATA_DIR, TARGETS_EXPIRES_DAYS

SPEC_VERSION = "1.0.0"
ROOT_JSON_PATH = DIRECTOR_METADATA_DIR / "root.json"

# 파일명 파서: name_X.Y.bin 형식
_RX_US  = re.compile(r'^(?P<name>.+?)_(?P<ver>\d+(?:\.\d+)*)(?P<ext>\.[^.]+)$')

def parse_name_version(filename: str) -> Optional[Tuple[str,str,str]]:
    m = _RX_US.match(filename)
    if m:
        ext = m.group('ext')
        return m.group('name'), m.group('ver'), ext
    return None

def _split_ver(ver: str) -> List[int]:
    return [int(x) for x in ver.split('.')]

def version_gt(a: str, b: str) -> bool:
    return _split_ver(a) > _split_ver(b)

def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def _sign_ed25519_pem(message: bytes, pem_path: str) -> str:
    key_data = Path(pem_path).read_bytes()
    sk = serialization.load_pem_private_key(key_data, password=None)
    if not isinstance(sk, Ed25519PrivateKey):
        raise TypeError("Expected Ed25519 private key")
    sig = sk.sign(message)
    return binascii.hexlify(sig).decode("ascii")

def _load_targets_keyid_from_root(root_path: Path = ROOT_JSON_PATH) -> str:
    if not root_path.exists():
        raise FileNotFoundError(f"root.json not found: {root_path}")
    root_raw = json.loads(root_path.read_text(encoding="utf-8"))
    body = root_raw.get("signed", root_raw)
    roles = body.get("roles") or {}
    t_role = roles.get("targets") or {}
    keyids = t_role.get("keyids") or []
    if not keyids:
        raise ValueError("No targets keyids found in root.json (roles.targets.keyids)")
    # thresholds = 1
    return keyids[0]

# def next_targets_version() -> int:
#     latest = 0
#     pat = re.compile(r"^(\d+)\.targets\.json$")
#     if DIRECTOR_METADATA_DIR.is_dir():
#         for name in os.listdir(DIRECTOR_METADATA_DIR):
#             m = pat.match(name)
#             if m:
#                 latest = max(latest, int(m.group(1)))
#     return latest + 1

def _write_targets_json(doc: Dict[str, Any]) -> Path:
    out = DIRECTOR_METADATA_DIR / "targets_per_vehicle.json"
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return out

def extract_installed_list_from_vvm(vvm_raw: Dict[str, Any]) -> List[Tuple[str,str,str,Dict[str,Any]]]:
    """
    반환: [(ecu_serial, filename, version_str, fileinfo_dict), ...]
    """
    out: List[Tuple[str,str,str,Dict[str,Any]]] = []
    body = vvm_raw.get("signed", vvm_raw)
    evs = body.get("ecu_version", []) or []
    for ev in evs:
        ecu_id = (ev or {}).get("ecu_serial") or ""
        img = (ev or {}).get("target_image") or {}
        if not isinstance(img, dict) or not img:
            continue
        fname = img.get("filename")
        finfo = img.get("fileinfo") or {}
        if not fname or not isinstance(finfo, dict):
            continue
        pv = parse_name_version(fname)
        if not pv:
            continue
        _, ver, _ = pv
        out.append((ecu_id, fname, ver, finfo))
    return out

def build_global_map_by_ecu(global_targets: Dict[str, Any]) -> Dict[str, Tuple[str, Dict[str, Any]]]:
    out: Dict[str, Tuple[str, Dict[str, Any]]] = {}
    arr = (global_targets.get("signed") or {}).get("targets") or []
    if not isinstance(arr, list):
        return out
    for item in arr:
        ecu = (item or {}).get("ecu_serial")
        ti  = (item or {}).get("target_image") or {}
        if not ecu or not isinstance(ti, dict):
            continue
        fname = ti.get("filename")
        finfo = ti.get("fileinfo") or {}
        if not fname or not isinstance(finfo, dict):
            continue
        out[ecu] = (fname, finfo)
    return out

# --- 메인: 비교 → per-vehicle targets(리스트 스키마) 생성/서명 ---
def make_targets_for_car(vvm_raw: Dict[str, Any], global_targets: Dict[str, Any]) -> Path:
    installed_list = extract_installed_list_from_vvm(vvm_raw)
    gmap = build_global_map_by_ecu(global_targets)

    selected_list: List[Dict[str, Any]] = []
    any_update = False

    for ecu_id, cur_fname, cur_ver, cur_finfo in installed_list:
        g = gmap.get(ecu_id)
        if not g:
            continue
        best_fname, best_finfo = g
        pv_best = parse_name_version(best_fname)
        pv_cur  = parse_name_version(cur_fname)
        if not pv_best or not pv_cur:
            continue
        _, best_ver, _ = pv_best

        need_update = False
        try:
            need_update = version_gt(best_ver, cur_ver)
        except Exception:
            cur_sha  = ((cur_finfo.get("hashes") or {}) or {}).get("sha256")
            best_sha = ((best_finfo.get("hashes") or {}) or {}).get("sha256")
            need_update = bool(cur_sha and best_sha and cur_sha != best_sha)

        if need_update:
            any_update = True
            selected_list.append({
                "ecu_serial": ecu_id,
                "target_image": {
                    "filename": best_fname,
                    "fileinfo": best_finfo
                }
            })

    now = datetime.now(timezone.utc)
    expires_str = (now + timedelta(days=TARGETS_EXPIRES_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    version = 1

    final_signed = {
        "_type": "targets",
        "spec_version": SPEC_VERSION,
        "version": version,
        "expires": expires_str,
        "targets": selected_list,
        "update": bool(any_update),
    }

    sign_key_path = DIRECTOR_KEYS_DIR / "target.pem"
    if not sign_key_path.exists():
        raise FileNotFoundError(f"Director signing key not found: {sign_key_path}")

    msg = canonical_json_bytes(final_signed)
    sig_b64 = _sign_ed25519_pem(msg, str(sign_key_path))
    targets_keyid = _load_targets_keyid_from_root()

    final_doc = {
        "signatures": [{"keyid": targets_keyid, "sig": sig_b64}],
        "signed": final_signed,
    }
    return _write_targets_json(final_doc)