import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

DISALLOWED_LICENSES = {
    # SPDX: only
    "GPL-3.0-only",
    "AGPL-3.0-only",
    "GPL-2.0-only",
    "LGPL-3.0-only",
    "LGPL-2.1-only",

    # SPDX: or-later
    "GPL-3.0-or-later",
    "AGPL-3.0-or-later",
    "GPL-2.0-or-later",
    "LGPL-3.0-or-later",
    "LGPL-2.1-or-later",

    # 비표준/약식 표기
    "GPL-3.0+",
    "AGPL-3.0+",
    "GPL-2.0+",
    "LGPL-3.0+",
    "LGPL-2.1+",
}

# 라이선스 문자열 다양성 방지 -> split용 정규식 활용
_SPLIT_RE = re.compile(r"[,\s;/|()]+|AND|OR", re.IGNORECASE)


def _load_json(p: Path) -> Dict[str, Any]:
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

# Trivy image vuln 결과에서 HIGH/CRITICAL 취약점 개수 확인
def _count_high_critical_vulns(cve: Dict[str, Any]) -> int:
    n = 0
    for r in cve.get("Results", []) or []:
        for v in (r.get("Vulnerabilities") or []):
            sev = str(v.get("Severity", "")).upper()
            if sev in ("HIGH", "CRITICAL"):
                n += 1
    return n


# Secrets 리스트가 1개라도 존재 -> 정책 위반으로 간주
def _has_secrets(fs: Dict[str, Any]) -> bool:
    for r in fs.get("Results", []) or []:
        secrets = r.get("Secrets") or []
        if secrets:
            return True
    return False


# Trivy가 반환한 라이선스 필드 토큰화
def _tokenize_license_field(lic_field: Any) -> List[str]:
    if not lic_field:
        return []

    if isinstance(lic_field, list):
        raw = " ".join(str(x) for x in lic_field if x)
    else:
        raw = str(lic_field)

    raw = raw.strip()
    if not raw:
        return []

    return [t.strip() for t in _SPLIT_RE.split(raw) if t and t.strip()]


# Trivy image license 결과에서 금지 라이선스 반환
def _find_disallowed_licenses(lic: Dict[str, Any]) -> Set[str]:
    found: Set[str] = set()

    # 패키지 기반 결과
    for r in lic.get("Results", []) or []:
        for p in (r.get("Packages") or []):
            lic_field = p.get("License")
            for t in _tokenize_license_field(lic_field):
                if t in DISALLOWED_LICENSES:
                    found.add(t)

    # 라이선스 목록 기반 결과
    for r in lic.get("Results", []) or []:
        for l in (r.get("Licenses") or []):
            name = l.get("Name") or l.get("License")
            for t in _tokenize_license_field(name):
                if t in DISALLOWED_LICENSES:
                    found.add(t)

    return found

# out_dir 내 결과 파일을 확인하여 정책 위반 여부 종합 판단
def main(out_dir: str) -> int:
    out = Path(out_dir)

    # run_all.sh가 저장한 JSON 결과 파일 로드
    cve = _load_json(out / "cve.json")
    lic = _load_json(out / "license.json")
    fs = _load_json(out / "fs.json")

    reasons: List[str] = []

    # HIGH/CRITICAL 취약점 존재 여부
    n_cve = _count_high_critical_vulns(cve)
    if n_cve > 0:
        reasons.append(f"HIGH/CRITICAL CVE detected: {n_cve}")

    # Secret 탐지 여부
    if _has_secrets(fs):
        reasons.append("Secret leakage detected (Trivy FS secret scanner)")

    # 금지 라이선스 포함 여부
    disallowed = _find_disallowed_licenses(lic)
    if disallowed:
        reasons.append("Disallowed license detected: " + ", ".join(sorted(disallowed)))

    # Malicious script marker 탐지 여부
    mh = out / "malicious_hits.txt"
    if mh.exists() and mh.read_text(encoding="utf-8").strip():
        reasons.append("Potentially malicious script markers detected (grep hits)")

    # 최종 판정 시, 위반 사유가 하나라도 있으면 FAIL(차단)
    if reasons:
        print("[Primary ECU] Static Verification FAILED")
        for r in reasons:
            print(f" - {r}")
        return 2

    print("[Primary ECU] Static Verification PASSED")
    print(" - No policy violations found")
    return 0


if __name__ == "__main__":
    # 사용법 체크
    if len(sys.argv) != 2:
        print("Usage: evaluate_policy.py <out_dir>", file=sys.stderr)
        sys.exit(1)

    sys.exit(main(sys.argv[1]))