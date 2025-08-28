from __future__ import annotations
import json, re, time, hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

# ---- 유틸: 버전 비교 (세자리/문자 혼합도 안전하게) ----
_version_token = re.compile(r'(\d+|[A-Za-z]+)')

def _split_ver(v: str) -> List[Any]:
    return [int(t) if t.isdigit() else t.lower() for t in _version_token.findall(v or "")]

def version_gt(a: str, b: str) -> bool:
    """a > b ? (semantic-ish 비교)"""
    A, B = _split_ver(a), _split_ver(b)
    # 길이 맞추기
    L = max(len(A), len(B))
    A += [0]*(L-len(A)); B += [0]*(L-len(B))
    return A > B

@dataclass
class EcuState:
    ecu_id: str
    hw_id: Optional[str]
    name: Optional[str]
    version: Optional[str]
    sha256: Optional[str]

def _pick_candidates_for_ecu(ecu: EcuState, vin: str, global_targets: Dict[str, Any]) -> List[tuple[str, Dict[str, Any]]]:
    out = []
    all_targets = global_targets.get("signed", {}).get("targets", {})
    for fname, meta in all_targets.items():
        custom = meta.get("custom", {})
        # deviceId 제한
        dev_ids = set(custom.get("deviceIds", []) or [])
        if dev_ids and vin not in dev_ids:
            continue
        # ecuId 제한
        ecu_ids = set(custom.get("ecuIds", []) or [])
        if ecu_ids and ecu.ecu_id not in ecu_ids:
            continue
        # hwId 제한
        hw_ids = set(custom.get("hardwareIds", []) or [])
        if hw_ids and (not ecu.hw_id or ecu.hw_id not in hw_ids):
            continue
        out.append((fname, meta))
    return out

def _needs_update(ecu: EcuState, candidate_meta: Dict[str, Any]) -> bool:
    # 현재 설치 정보가 없으면 → 업데이트 필요
    if not ecu.name or not ecu.version or not ecu.sha256:
        return True
    cand_custom = candidate_meta.get("custom", {})
    cand_ver = str(cand_custom.get("version", "")) or ""
    cand_hash = (candidate_meta.get("hashes", {}) or {}).get("sha256", "")

    # 같은 파일/해시면 불필요
    if cand_hash and ecu.sha256 and cand_hash == ecu.sha256:
        return False
    # 버전 비교 우선(버전 있으면)
    if cand_ver and ecu.version:
        try:
            return version_gt(cand_ver, ecu.version)
        except Exception:
            # 버전 파싱 실패 시 해시/이름 변경만으로도 업데이트 판단
            return (ecu.name != cand_custom.get("name")) or (cand_hash and cand_hash != ecu.sha256)
    # 마지막 방어: 이름/해시가 다르면 업데이트
    return (cand_hash and cand_hash != ecu.sha256) or (ecu.name != cand_custom.get("name"))

def select_updates_for_vehicle(vehicle_manifest: Dict[str, Any],
                               global_targets: Dict[str, Any]) -> Dict[str, Any]:
    """
    차량 전용(per-vehicle) targets 생성(미서명).
    반환 스키마: Uptane targets와 동일한 상위 구조 유지.
    """
    vin = vehicle_manifest.get("vin", "")
    ecus_in = vehicle_manifest.get("ecus", {})

    selected: Dict[str, Any] = {}
    reasons: Dict[str, str] = {}

    for ecu_id, info in ecus_in.items():
        ecu = EcuState(
            ecu_id=ecu_id,
            hw_id=info.get("hw_id"),
            name=(info.get("installed") or {}).get("name"),
            version=(info.get("installed") or {}).get("version"),
            sha256=(info.get("installed") or {}).get("sha256"),
        )
        candidates = _pick_candidates_for_ecu(ecu, vin, global_targets)
        if not candidates:
            continue

        # 같은 컴포넌트/ECU용 후보 중 "가장 높은 버전"을 선택
        def _cand_key(item):
            _, meta = item
            ver = str(meta.get("custom", {}).get("version", "")) or ""
            return _split_ver(ver)

        candidates.sort(key=_cand_key, reverse=True)

        for fname, meta in candidates:
            if _needs_update(ecu, meta):
                # per-vehicle에 포함
                selected[fname] = meta
                reasons[ecu_id] = f"{ecu.version or 'none'} -> {meta.get('custom', {}).get('version','?')}"
                break

    # 미서명 targets 문서 생성
    now = int(time.time())
    expires = now + 24*3600  # 네가 원했던 '만료 1일' 기본값
    signed_block = {
        "type": "targets",
        "version": int(now),             # 간단 버전 증가: epoch 사용(실서비스는 카운터 권장)
        "expires": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires)),
        "targets": selected,
        # 필요하면 delegations 넣기(하위위임/threshold 등)
        # "delegations": {...}
    }

    unsigned_doc = {
        "signed": signed_block,
        "signatures": []   # 서명 전이므로 빈 배열
    }

    debug_info = {"reasons": reasons, "selected_count": len(selected)}
    return {"targets_doc": unsigned_doc, "debug": debug_info}

# ---- 파일 입출력 헬퍼 ----
def save_per_vehicle_targets(doc: Dict[str, Any], out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
