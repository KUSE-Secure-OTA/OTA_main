from dataclasses import dataclass
from typing import Optional
import os, shutil

from .storage import Storage

@dataclass
class InstallResult:
    ok: bool
    reason: Optional[str] = None

class Installer:
    def __init__(self, storage: Storage):
        self.storage = storage

    def install(self, image_path: str, version: str) -> InstallResult:
        try:
            staging = self.storage.staging_dir(version)
            os.makedirs(staging, exist_ok=True)
            shutil.copy2(image_path, os.path.join(staging, os.path.basename(image_path)))

            active = self.storage.active_symlink()
            try:
                if os.path.islink(active):
                    os.unlink(active)
                if os.path.exists(active) and not os.path.islink(active):
                    raise RuntimeError(f"active path exists and is not symlink: {active}")
                os.symlink(staging, active)
            except (OSError, NotImplementedError):
                # symlink 불가 환경 폴백: 디렉터리 복사
                fallback = active if os.path.isdir(active) else active + "_dir"
                if os.path.exists(fallback):
                    shutil.rmtree(fallback, ignore_errors=True)
                shutil.copytree(staging, fallback)

            self.storage.write_version(version)
            return InstallResult(ok=True)
        except Exception as e:
            return InstallResult(ok=False, reason=str(e))

    def rollback(self):
        prev = self.storage.last_good_version()
        if not prev:
            raise RuntimeError("no previous version to rollback")
        active = self.storage.active_symlink()
        if os.path.islink(active):
            os.unlink(active)
        try:
            os.symlink(self.storage.staging_dir(prev), active)
        except (OSError, NotImplementedError):
            fallback = active if os.path.isdir(active) else active + "_dir"
            if os.path.exists(fallback):
                shutil.rmtree(fallback, ignore_errors=True)
            shutil.copytree(self.storage.staging_dir(prev), fallback)
