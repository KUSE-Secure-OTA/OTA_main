#!/usr/bin/env python3
import argparse
import json
import re
import sys
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


# SBOM forbidden components
FORBIDDEN_COMPONENTS = {
    # networking / sniffing / pivot
    "tcpdump", "wireshark", "tshark", "nmap", "masscan", "socat", "netcat",
    "netcat-openbsd", "ncat",
    # debugging / tracing / build tools
    "gdb", "strace", "ltrace", "perf",
    "gcc", "g++", "clang", "make", "cmake",
}

# License policy
# FAIL: AGPL only
# WARN: GPL/LGPL
FAIL_LICENSES = {
    # Normalize to uppercase tokens (see _tokenize_license_field)
    "AGPL-3.0",
    "AGPL-3.0-ONLY",
    "AGPL-3.0-OR-LATER",
    "AGPL-3.0+",
}

WARN_LICENSES = {
    # SPDX: only
    "GPL-3.0-only",
    "GPL-2.0-only",
    "LGPL-3.0-only",
    "LGPL-2.1-only",
    # SPDX: or-later
    "GPL-3.0-or-later",
    "GPL-2.0-or-later",
    "LGPL-3.0-or-later",
    "LGPL-2.1-or-later",
    # Shorthand
    "GPL-3.0+",
    "GPL-2.0+",
    "LGPL-3.0+",
    "LGPL-2.1+",
}

# Secret: sensitive paths (presence => FAIL)
SENSITIVE_PATH_PREFIXES = (
    "/app/.env",
    "/root/.aws",
    "/etc",
    "/home",
)

# Secret filter (Trivy varies by version)
SECRET_SEV = {"HIGH", "CRITICAL"}

# Entrypoint/CMD/history malicious markers (presence => FAIL)
MALICIOUS_RE = re.compile(
    r"(curl\s+[^|\n]+\|\s*(bash|sh))"
    r"|(wget\s+[^|\n]+\|\s*(bash|sh))"
    r"|(nc\s+[^\n]*\s-e\s+/bin/(ba)?sh)"
    r"|(base64\s+-d\s*\|\s*(bash|sh))",
    re.IGNORECASE,
)

# License token split helper
_SPLIT_RE = re.compile(r"[,\s;/|()]+|AND|OR", re.IGNORECASE)


# Helpers
def _load_json(p: Path) -> Dict[str, Any]:
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _tokenize_license_field(x: Any) -> List[str]:
    if not x:
        return []
    raw = " ".join(map(str, x)) if isinstance(x, list) else str(x)
    raw = raw.strip()
    if not raw:
        return []
    # Normalize: uppercase tokens for robust matching across Trivy versions/formats
    return [t.strip().upper() for t in _SPLIT_RE.split(raw) if t and t.strip()]


def normalize_path(p: str) -> str:
    p = (p or "").replace("\\", "/").strip()
    if ":" in p and not p.startswith("/"):
        p = p.split(":", 1)[1].lstrip("/")
    p = re.sub(r"^(rootfs/)+", "", p)
    if not p.startswith("/"):
        p = "/" + p
    return p


def is_sensitive_path(path: str) -> bool:
    np = normalize_path(path)
    return any(np.startswith(prefix) for prefix in SENSITIVE_PATH_PREFIXES)


# SBOM (CycloneDX) => forbidden presence
def sbom_component_names(sbom: Dict[str, Any]) -> Set[str]:
    names: Set[str] = set()
    for c in (sbom.get("components") or []):
        name = str(c.get("name") or "").strip().lower()
        if name:
            names.add(name)
    return names


def find_forbidden_components(sbom: Dict[str, Any]) -> List[str]:
    names = sbom_component_names(sbom)
    hits = sorted([n for n in names if n in FORBIDDEN_COMPONENTS])
    return hits


# CVE => WARN only
def vuln_counts(cve: Dict[str, Any]) -> Dict[str, int]:
    cnt = {"CRITICAL": 0, "HIGH": 0}
    for r in (cve.get("Results") or []):
        for v in (r.get("Vulnerabilities") or []):
            sev = str(v.get("Severity") or "").upper()
            if sev in cnt:
                cnt[sev] += 1
    return cnt


# Secret (Trivy secret) => FAIL on sensitive paths
def secret_findings(fs: Dict[str, Any]) -> List[Tuple[str, str]]:
    hits: List[Tuple[str, str]] = []
    for r in (fs.get("Results") or []):
        secrets = r.get("Secrets") or []
        if not isinstance(secrets, list):
            continue

        # Some Trivy outputs place file target at result-level
        r_target = str(r.get("Target") or "").strip()

        for s in secrets:
            # Trivy can include null entries in Secrets; skip non-dict safely
            if not isinstance(s, dict):
                continue

            sev = str(s.get("Severity") or "").upper()
            conf = str(s.get("Confidence") or "").upper()

            ok = (sev in SECRET_SEV) or (conf == "HIGH")
            if not ok:
                continue

            loc = s.get("Location") or {}
            if not isinstance(loc, dict):
                loc = {}

            # Expand path candidates for Trivy version differences
            path = str(
                loc.get("Path")
                or loc.get("File")
                or loc.get("FilePath")
                or s.get("Target")
                or s.get("FilePath")
                or r_target
                or ""
            ).strip()

            if path:
                hits.append((path, sev or conf or "HIGH"))
    return hits


# Archive config inspection (oci-archive + docker-archive)
def _tar_has(tf: tarfile.TarFile, name: str) -> bool:
    try:
        tf.getmember(name)
        return True
    except KeyError:
        return False


def _read_json_member(tf: tarfile.TarFile, member_name: str) -> Dict[str, Any]:
    m = tf.getmember(member_name)
    f = tf.extractfile(m)
    if f is None:
        return {}
    return json.loads(f.read().decode("utf-8"))


def _join_list(v: Any) -> str:
    if isinstance(v, list):
        return " ".join(map(str, v))
    if isinstance(v, str):
        return v
    return ""


def extract_image_config_text(archive_path: str) -> str:
    parts: List[str] = []
    with tarfile.open(archive_path, "r:*") as tf:
        if _tar_has(tf, "index.json"):
            index = _read_json_member(tf, "index.json")
            manifests = index.get("manifests") or []
            if not manifests:
                return ""

            manifest_digest = manifests[0]["digest"]
            algo, hexd = manifest_digest.split(":", 1)
            manifest_path = f"blobs/{algo}/{hexd}"
            mani = _read_json_member(tf, manifest_path)

            config_digest = mani["config"]["digest"]
            algo2, hexd2 = config_digest.split(":", 1)
            config_path = f"blobs/{algo2}/{hexd2}"
            cfg = _read_json_member(tf, config_path)

        elif _tar_has(tf, "manifest.json"):
            manifest = _read_json_member(tf, "manifest.json")
            if not isinstance(manifest, list) or not manifest:
                return ""
            cfg_name = manifest[0].get("Config")
            if not cfg_name:
                return ""
            cfg = _read_json_member(tf, cfg_name)

        else:
            return ""

        c = cfg.get("config") or {}
        parts.append(_join_list(c.get("Entrypoint")))
        parts.append(_join_list(c.get("Cmd")))

        for h in (cfg.get("history") or []):
            cb = h.get("created_by")
            if cb:
                parts.append(str(cb))

    return "\n".join([p for p in parts if p])


# License => FAIL on AGPL, WARN on GPL/LGPL
def classify_licenses(lic: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
    fail: Set[str] = set()
    warn: Set[str] = set()

    for r in (lic.get("Results") or []):
        # Newer formats
        for p in (r.get("Packages") or []):
            for t in _tokenize_license_field(p.get("License")):
                if t in FAIL_LICENSES:
                    fail.add(t)
                elif t in WARN_LICENSES:
                    warn.add(t)

        for l in (r.get("Licenses") or []):
            name = l.get("Name") or l.get("License")
            for t in _tokenize_license_field(name):
                if t in FAIL_LICENSES:
                    fail.add(t)
                elif t in WARN_LICENSES:
                    warn.add(t)

    # if AGPL exists, we still keep WARNs for reporting, but decision is FAIL anyway
    return fail, warn


# Main decision: PASS / PASS(WARN) / FAIL
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir", help="Directory containing sbom.json/cve.json/license.json/fs.json")
    ap.add_argument("--archive", required=True, help="image archive path (oci-archive or docker-archive)")
    args = ap.parse_args()

    out = Path(args.out_dir)
    sbom = _load_json(out / "sbom.json")
    cve = _load_json(out / "cve.json")
    lic = _load_json(out / "license.json")
    fs = _load_json(out / "fs.json")

    reasons: List[str] = []   # FAIL
    warnings: List[str] = []  # WARN (continue to dynamic verification)

    # 1. SBOM forbidden components => FAIL
    forbidden = find_forbidden_components(sbom)
    if forbidden:
        reasons.append("Forbidden components found in SBOM: " + ", ".join(forbidden[:25]))

    # 2. License => FAIL on AGPL, WARN on GPL/LGPL
    lic_fail, lic_warn = classify_licenses(lic)
    if lic_fail:
        reasons.append("Disallowed license detected (FAIL): " + ", ".join(sorted(lic_fail)))
    if lic_warn:
        warnings.append("License findings (WARN): " + ", ".join(sorted(lic_warn)))

    # 3. Secret => FAIL (sensitive paths only)
    hits = secret_findings(fs)
    sensitive_hits = [(p, s) for (p, s) in hits if is_sensitive_path(p)]
    if sensitive_hits:
        sample = ", ".join([normalize_path(p) for (p, _) in sensitive_hits[:5]])
        reasons.append(f"Secret leakage in sensitive paths: {len(sensitive_hits)} findings (e.g., {sample})")

    # 4. Entrypoint/CMD/history => FAIL if malicious pattern
    try:
        txt = extract_image_config_text(args.archive)
        if txt and MALICIOUS_RE.search(txt):
            reasons.append("Potentially malicious pattern found in ENTRYPOINT/CMD/build history")
    except Exception as e:
        warnings.append(f"Failed to inspect image config (non-fatal): {e}")

    # 5. CVE => WARN only
    vc = vuln_counts(cve)
    if vc["CRITICAL"] > 0 or vc["HIGH"] > 0:
        warnings.append(f"CVE findings (signal only): CRITICAL={vc['CRITICAL']}, HIGH={vc['HIGH']}")

    # Decision
    if reasons:
        print("[Primary ECU] Static Verification FAILED")
        for r in reasons:
            print(f" - {r}")
        if warnings:
            print("[Primary ECU] Warnings (ignored for fail decision):")
            for w in warnings:
                print(f" - {w}")
        return 2

    if warnings:
        print("[Primary ECU] Static Verification PASSED (WITH WARNINGS)")
        for w in warnings:
            print(f" - {w}")
        return 0

    print("[Primary ECU] Static Verification PASSED")
    print(" - No policy violations found")
    return 0


if __name__ == "__main__":
    sys.exit(main())