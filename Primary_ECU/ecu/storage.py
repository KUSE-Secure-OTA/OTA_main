import os, json, time
from typing import Optional

class Storage:
    """버전/상태/경로 관리를 담당하는 로컬 스토리지 래퍼."""

    def __init__(self, base: str | None = None):
        # 권한/이식성 고려하여 사용자 홈 하위 기본 경로 사용
        self.base = base or os.path.expanduser("~/.primary_ecu")
        os.makedirs(self.base, exist_ok=True)
        self._state = os.path.join(self.base, "state.json")
        self._ver   = os.path.join(self.base, "version.json")

    # ── 경로 유틸 ───────────────────────────────────────────────────────────
    def meta_path(self, version: str) -> str:
        p = os.path.join(self.base, "meta", f"{version}.json")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def image_path(self, version: str) -> str:
        p = os.path.join(self.base, "images", f"{version}.bin")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def staging_dir(self, version: str) -> str:
        p = os.path.join(self.base, "staging", version)
        os.makedirs(p, exist_ok=True)
        return p

    def active_symlink(self) -> str:
        return os.path.join(self.base, "current")

    # ── 상태 기록 ───────────────────────────────────────────────────────────
    def save_state(self, data: dict):
        payload = dict(data)
        payload.setdefault("_ts", int(time.time()))
        with open(self._state, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

    def write_version(self, version: str):
        with open(self._ver, "w", encoding="utf-8") as f:
            json.dump({"current": version}, f)

    def last_good_version(self) -> Optional[str]:
        if not os.path.exists(self._ver):
            return None
        with open(self._ver, "r", encoding="utf-8") as f:
            return json.load(f).get("current")
