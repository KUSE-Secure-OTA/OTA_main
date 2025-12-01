from dataclasses import dataclass
from typing import Optional, Union, Dict, Any, List
from urllib.parse import urljoin
from pathlib import Path
import os, shutil, json
import requests
from utils.fastcdc_chunking import join_all_by_manifest, load_image_from_oci, run_container

from .storage import Storage

@dataclass
class InstallResult:
    ok: bool
    reason: Optional[str] = None

class Installer:
    def __init__(self, storage: Storage):
        self.storage = storage

    def build_image_manifest_url(self, base_url, ecu, image_name):
        filename = f"{image_name}.json"
        return f"{base_url}/meta/targets/{ecu}/{ecu}_image/{filename}"
    
    def build_image_chunk_url(self, base_url, chunk_name):
        return f"{base_url}/chunks/{chunk_name}"

    # Chunk 다운로드 및 재조립
    def download_chunk(self, update_images:List, base_url:str):

        for t in update_images:
            chunk_list = t["images"]["required_chunks"]

            for c in chunk_list:
                url = self.build_image_chunk_url(base_url, c)
                out_path = f"./downloads/chunk_storage/{c}"
                print(f"[Primary ECU] GET:  {url}")

                try:
                    with requests.get(url, stream=True, verify=False) as response:
                        response.raise_for_status()
                        with open(out_path, "wb") as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                if chunk:
                                    f.write(chunk)
                    print(f"[OK] saved chunk -> {out_path}")
                except Exception as e:
                    print(f"[FAIL] failed to download chunk {c} from {url}: {e}")

            # 재조립
            image_name = t["images"]["image_name"]
            manifest_path = f"./downloads/{image_name}.json"
            reassembled_path = f"./downloads/{image_name}"
            metrics, t = join_all_by_manifest(manifest_path, reassembled_path, "./downloads/chunk_storage")
            print(f"[Primary ECU] Reassemble:   {reassembled_path}")
            load_image_from_oci(reassembled_path)
            run_container()

    # Manifest 다운로드 -> 컨테이너 재조립을 위한 chunk 목록
    def download_manifest(self, update_images:List, base_url:str):

        for t in update_images:
            ecu = t["ecu"]
            image_name = t["images"]["image_name"]

            url = self.build_image_manifest_url(base_url, ecu, image_name)
            print(f"[Primary ECU] GET:  {url}")

            resp = requests.get(url, verify=False)
            if resp.status_code != 200:
                # 상황에 따라 raise / continue 등 정책 선택
                raise RuntimeError(f"Failed to fetch {url}: {resp.status_code}")

            image_meta = resp.json()
            save_path = Path(f"./downloads/{image_name}.json")
            save_path.write_text(json.dumps(image_meta, indent=2, ensure_ascii=False), encoding="utf-8")




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
