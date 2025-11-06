import os, json
from typing import Optional

class Storage:
    def __init__(self, base: str = None):
        # 개발/WSL에선 사용자 홈 밑에 두는 게 권한 문제 적음
        self.base = base or os.path.expanduser("~/.primary_ecu")
        os.makedirs(self.base, exist_ok=True)
        self._state = os.path.join(self.base, "state.json")
        self._ver = os.path.join(self.base, "version.json")

    def meta_path(self, version: str) -> str:
        p = os.path.join(self.base, "meta", f"{version}.json")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def image_path(self, version: str) -> str:
        p = os.path.join(self.base, "images", f"{version}.bin")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def staging_dir(self, version: str) -> str:
        return os.path.join(self.base, "staging", version)

    def active_symlink(self) -> str:
        return os.path.join(self.base, "current")

    def save_state(self, data: dict):
        with open(self._state, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def write_version(self, version: str):
        with open(self._ver, "w", encoding="utf-8") as f:
            json.dump({"current": version}, f)

    def last_good_version(self) -> Optional[str]:
        if not os.path.exists(self._ver): return None
        with open(self._ver, "r", encoding="utf-8") as f:
            return json.load(f).get("current")
