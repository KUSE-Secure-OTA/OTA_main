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
            if os.path.islink(active): os.unlink(active)
            os.symlink(staging, active)

            self.storage.write_version(version)
            return InstallResult(ok=True)
        except Exception as e:
            return InstallResult(ok=False, reason=str(e))

    def rollback(self):
        prev = self.storage.last_good_version()
        if not prev:
            raise RuntimeError("no previous version to rollback")
        active = self.storage.active_symlink()
        if os.path.islink(active): os.unlink(active)
        os.symlink(self.storage.staging_dir(prev), active)
