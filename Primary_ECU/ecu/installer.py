from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Union, Dict, Any, List
from urllib.parse import urljoin
from pathlib import Path
import os, shutil, json, subprocess
import requests
import socket, time
from utils.fastcdc_chunking import join_all_by_manifest
from utils.fastcdc_chunking import load_image_from_oci
from utils.fastcdc_chunking import load_image_from_tar
from utils.fastcdc_chunking import run_container
from make_vvm import load_or_create_ed25519_private_key, calc_ed25519_keyid_from_public_key, sign_block_ed25519
from utils.metrics import measure
from .storage import Storage

# -------------------------------------------------------------------
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
# -------------------------------------------------------------------

SYSTEM = os.environ.get("SYSTEM_NAME", "")
TC = os.environ.get("TEST_CASE", "")

@dataclass
class InstallResult:
    ok: bool
    reason: Optional[str] = None

class Installer:
    def __init__(
        self,
        storage: Storage,
        namespace: str = "default",
        spawner_host: str = "127.0.0.1",
        spawner_nodeport: int = 31321,  # deployment.yaml의 nodePort 기본값 :contentReference[oaicite:2]{index=2}
        # -----------------
        # 환경에 맞게 변경
        # -----------------
        host_io_dir: str = "/home/kuse/ota/dynamic_testing/agent-io",
    ):
        self.storage = storage
        self.namespace = namespace
        self.spawner_host = spawner_host
        self.spawner_nodeport = spawner_nodeport
        self.host_io_dir = str(Path(host_io_dir).expanduser().resolve())

    # -------------------------------------------------------------------
    def _make_session(self) -> requests.Session:
        s = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(
            max_retries=retries,
            pool_connections=32,
            pool_maxsize=32,
        )
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    def _download_one_chunk(self, session: requests.Session, url: str, out_path: str) -> None:
        # 이미 있으면 스킵(캐시)
        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            return

        tmp_path = out_path + ".part"
        os.makedirs(os.path.dirname(out_path), exist_ok=True)

        with session.get(url, stream=True, verify=False, timeout=(5, 120)) as r:
            r.raise_for_status()
            with open(tmp_path, "wb") as f:
                # 8KB는 너무 작아서 오버헤드 큼 → 1MB로 키우는 게 체감 큼
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        f.write(chunk)

        os.replace(tmp_path, out_path)
    # -------------------------------------------------------------------

    def _run(self, cmd: List[str]) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, check=True, capture_output=True, text=True)

    def _kubectl_json(self, args: List[str]) -> Any:
        return json.loads(self._run(["kubectl"] + args).stdout)

    def _get_node_ip(self) -> str:
        nodes = self._kubectl_json(["get", "nodes", "-o", "json"])
        addrs = nodes["items"][0]["status"]["addresses"]
        internal = [a["address"] for a in addrs if a["type"] == "InternalIP"]
        external = [a["address"] for a in addrs if a["type"] == "ExternalIP"]
        if internal:
            return internal[0]
        if external:
            return external[0]
        raise RuntimeError("노드 IP를 찾지 못했습니다.")

    def _get_nodeport(self, port: int = 4321) -> int:
        svc = self._kubectl_json(["-n", self.namespace, "get", "svc", self.spawner_service, "-o", "json"])
        for p in svc.get("spec", {}).get("ports", []):
            if int(p.get("port", -1)) == int(port) and "nodePort" in p:
                return int(p["nodePort"])
        raise RuntimeError(f"nodePort not found: {self.namespace}/{self.spawner_service} port={port}")
    
    def _trigger_spawner(self, *, test_img: str) -> None:
        # go spawner: "wake <test-image>" 형태만 읽는 전제(추가 필드는 있어도 무시 가능)
        payload = f"wake {test_img}\n".encode()
        with socket.create_connection((self.spawner_host, self.spawner_nodeport), timeout=5) as s:
            s.sendall(payload)

    def build_image_manifest_url(self, base_url, ecu, image_name):
        filename = f"{image_name}.json"
        return f"{base_url}/meta/targets/{ecu}/{ecu}_image/{filename}"
    
    def build_image_chunk_url(self, base_url, chunk_name):
        return f"{base_url}/chunks/{chunk_name}"

    def convert_oci_dir_to_tar(self, oci_dir: str, out_tar: str):
        # oci-dir을 podman 이미지로 로드
        out_tar = str(out_tar)

        try:
            os.remove(out_tar)
        except FileNotFoundError:
            pass

        image_ref = load_image_from_oci(oci_dir)

        subprocess.run(["podman", "save", "--format", "docker-archive", "-o", out_tar, image_ref], check=True)
        # subprocess.run(["podman", "rmi", "-f", image_ref], check=False)

    # Static verification pipeline 실행
    def run_static_verification(self, archive_path: str):
        
        env = os.environ.copy()
        env["ARCHIVE"] = archive_path   # shell pipeline에서 사용할 환경 변수

        # static/run_all.sh 경로 자동 설정
        static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
        runall = os.path.join(static_dir, "run_all.sh")

        print(f"[Primary ECU] Static Verification Start  ->  {archive_path}")
        
        result = subprocess.run(
            ["bash", runall, archive_path],
            env=env,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(result.stdout)
            print(result.stderr)
            raise RuntimeError("Static verification FAILED for: " + archive_path)

        print("[Primary ECU] Static Verification PASSED")

    def run_dynamic_verification(
        self,
        archive_path: str,
        *,
        test_img: str,
        tar_name: Optional[str] = None,
        timeout_sec: int = 600,
        fail_on_warn: bool = False,
    ) -> None:
        host_dir = Path(self.host_io_dir)
        host_dir.mkdir(parents=True, exist_ok=True)

        src = Path(archive_path).expanduser().resolve()
        if not src.exists():
            raise FileNotFoundError(f"archive not found: {src}")

        # tar 이름 결정 (agent.sh는 /in/*.tar 중 최신 파일을 집음)
        if not tar_name:
            tar_name = src.name
        if not tar_name.endswith(".tar"):
            tar_name = f"{tar_name}.tar"

        # 이전 tar들이 남아있으면 최신 선택이 꼬일 수 있어서 정리(순차 실행 전제)
        for old in host_dir.glob("*.tar"):
            try:
                old.unlink()
            except Exception:
                pass

        # 이전 결과 정리
        report_path = host_dir / "report.txt"
        if report_path.exists():
            report_path.unlink()

        art_dir = host_dir / "artifacts"
        if art_dir.exists() and art_dir.is_dir():
            shutil.rmtree(art_dir)

        for p in ("podman_load.log", "run_id.txt"):
            fp = host_dir / p
            if fp.exists():
                try:
                    fp.unlink()
                except Exception:
                    pass

        # agent가 /in에서 읽을 tar를 hostPath에 복사 + mtime 최신화
        dest_tar = host_dir / tar_name
        shutil.copyfile(src, dest_tar)
        os.utime(dest_tar, None)

        # spawner 트리거 (TEST_IMG만 넘김)
        self._trigger_spawner(test_img=test_img)

        # agent.sh가 마지막까지 진행했는지 판단용 마커(항상 report에 남도록 구성한 문구)
        need_markers = ("verification probe", "sensitive write")
        deadline = time.time() + timeout_sec

        last_txt = ""
        while time.time() < deadline:
            if report_path.exists():
                txt = report_path.read_text(errors="ignore")

                # 완료 근사 조건: 주요 섹션(6,7) 결과 라인이 report에 찍혔는지
                if all(m in txt for m in need_markers):
                    last_txt = txt
                    break

                last_txt = txt

            time.sleep(1.0)

        if not last_txt or not report_path.exists():
            raise TimeoutError(f"dynamic verification timeout (no report in {report_path})")

        # 판정: [FAIL] 있으면 실패, 옵션이면 [WARN]도 실패 처리
        lines = last_txt.splitlines()
        has_fail = any(line.startswith("[FAIL]") for line in lines)
        has_warn = any(line.startswith("[WARN]") for line in lines)

        if has_fail:
            raise RuntimeError("dynamic verification FAILED (see report.txt)")

        if fail_on_warn and has_warn:
            raise RuntimeError("dynamic verification WARN treated as FAIL (see report.txt)")

        return

    # Chunk 다운로드 및 재조립
    def download_chunk(self, update_images: List, base_url: str):
        updated_ecu_versions = []
        for t in update_images:
            with measure("Download Chunks", system_name=SYSTEM, test_case=TC):
                chunk_list = t["images"]["required_chunks"]

                # -------------------------------------------------------------------
                seen = set()
                uniq = []
                for c in chunk_list:
                    if c not in seen:
                        seen.add(c)
                        uniq.append(c)
                chunk_list = uniq

                session = self._make_session()

                max_workers = int(os.environ.get("CHUNKS_DL_WORKERS", "8"))

                futures = []
                with ThreadPoolExecutor(max_workers=max_workers) as ex:
                    for c in chunk_list:
                        url = self.build_image_chunk_url(base_url, c)
                        out_path = f"./downloads/chunk_storage/{c}"
                        futures.append(ex.submit(self._download_one_chunk, session, url, out_path))

                    # 에러를 여기서 모아서 한번에 터뜨리기
                    for i, fut in enumerate(as_completed(futures), 1):
                        exc = fut.exception()
                        if exc is not None:
                            raise RuntimeError(f"chunk download failed: {exc}") from exc

                        # 진행률 로그(원하시면)
                        if i % 50 == 0 or i == len(futures):
                            print(f"[Primary ECU] downloaded {i}/{len(futures)} chunks (workers={max_workers})")
                # -------------------------------------------------------------------

                # for c in chunk_list:
                #     url = self.build_image_chunk_url(base_url, c)
                #     out_path = f"./downloads/chunk_storage/{c}"
                #     print(f"[Primary ECU] GET:  {url}")

                #     try:
                #         with requests.get(url, stream=True, verify=False) as response:
                #             response.raise_for_status()
                #             with open(out_path, "wb") as f:
                #                 for chunk in response.iter_content(chunk_size=8192):
                #                     if chunk:
                #                         f.write(chunk)
                #         print(f"[OK] saved chunk -> {out_path}")
                    
                #     except Exception as e:
                #         print(f"[FAIL] failed to download chunk {c} from {url}: {e}")

            # 재조립
            with measure("Reassemble chunks", system_name=SYSTEM, test_case=TC):
                image_name = t["images"]["image_name"]
                manifest_path = f"./downloads/{image_name}.json"
                oci_dir = f"./downloads/{image_name}"

                metrics, tt = join_all_by_manifest(
                    manifest_path,
                    oci_dir,
                    "./downloads/chunk_storage"
                )
                print(f"[Primary ECU] Reassembled (OCI-DIR): {oci_dir}")

            # OCI DIR → OCI TAR 변환 (정적 검증 입력)
            archive_path = f"./downloads/{image_name}.tar"

            with measure("", system_name=SYSTEM, test_case=TC):
                self.convert_oci_dir_to_tar(oci_dir, archive_path)
                print(f"[Primary ECU] Packed OCI layout into archive: {archive_path}")

            # VVM Update
            with open("vvm.json", "r", encoding="utf-8") as f:
                vvm = json.load(f)

            for ecu in vvm["signed"]["ecu_version"]:
                if ecu.get("ecu_serial") == t["ecu"]:
                    ecu["target_image"]["filename"] = f"{image_name}.tar"
                    ecu["target_image"]["fileinfo"]["hashes"]["sha256"] = \
                        t["images"]["image_info"]["hashes"]["sha256"]
                    ecu["target_image"]["fileinfo"]["hashes"]["sha512"] = \
                        t["images"]["image_info"]["hashes"]["sha512"]
                    updated_ecu_versions.append(ecu)
                    break

            # Static Verification
            # self.run_static_verification(str(Path(archive_path).resolve()))

            # Dynamic Verification (정적 통과 후에만 실행)
            print("[Primary ECU] Run Dynamic Verification")
            with measure("Dynamic Verification", system_name=SYSTEM, test_case=TC):
                test_img = f"localhost/{image_name}:under-test"
                tar_name = f"{image_name}.tar"  # 충돌 방지용(호스트에 저장되는 tar 파일명)
                self.run_dynamic_verification(
                    str(Path(archive_path).resolve()),
                    test_img=test_img,
                    tar_name=tar_name,
                    timeout_sec=2400,
                    # fail_on_warn=False,  # 필요하면 True로
                )

            # 동적 실행
            # subprocess.run(["podman", "load", "-i", archive_path], check=True)
            # run_container()

        return updated_ecu_versions

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

            # 이미지 재활용 여부 확인
            installed_list_path = "./meta/installed_layers.json"
            if not os.path.exists(installed_list_path):
                installed = {"layers": []}
            else:
                with open(installed_list_path, 'r') as f:
                    installed = json.load(f)

            installed_hashes = set(installed.get("layers", []))

            chunks = image_meta["signed"]["chunks"]

            target_hashes = set()
            for key in chunks.keys():
                if key.startswith("blobs/sha256/"):
                    sha = key.split("blobs/sha256/")[1]
                    target_hashes.add(sha)

            new_layers = [h for h in target_hashes if h not in installed_hashes]

            if new_layers:
                installed_hashes.update(new_layers)

                # with open(installed_list_path, 'w') as f:
                #     json.dump({"layers": list(installed_hashes)}, f, indent=2)

                return list(installed_hashes)
            
            return []

    def download_image(self, update_images:List, base_url:str):
        with measure("Download Images", system_name=SYSTEM, test_case=TC):
            for image in update_images:
                image_name = image["images"]["image_name"]
                image_path = f"{base_url}/images/{image_name}.tar"
                out_path = f"./downloads/image_storage/{image_name}.tar"

                print(f"[Primary ECU] GET:      {image_path}")

                try:
                    with requests.get(image_path, stream=True, verify=False) as response:
                        response.raise_for_status()
                        with open(out_path, "wb") as f:
                            for image in response.iter_content(chunk_size=8192):
                                if image:
                                    f.write(image)
                    print(f"[OK] saved image -> {out_path}")
                except Exception as e:
                    print(f"[FAIL] failed to download chunk {image_name} from {image_path}: {e}")

        with measure("Build container image", system_name=SYSTEM, test_case=TC):
            load_image_from_tar(out_path)

        version = image_name.split('_')[1]
        major, minor, patch = map(int, version.split('.'))
        if major == 3:
            major = 0
        else:
            major -= 1
        version = f"{major}.{minor}.{patch}"
        # run_container(version)

    def update_info(self, layer_list, vvm_version):
        # 설치된 레이어 리스트 업데이트
        with open("./meta/installed_layers.json", 'w') as f:
            json.dump({"layers": layer_list}, f, indent=2)

        # VVM 업데이트
        ED25519_PRIVATE_KEY_PATH = Path("ed25519_private_key.pem")
        vin = "VIN-TEST-0001"
        primary_ecu_serial = "primary0"
        ed_private_key = load_or_create_ed25519_private_key(ED25519_PRIVATE_KEY_PATH)

        vvm_keyid = calc_ed25519_keyid_from_public_key(ed_private_key)

        now = datetime.now(timezone.utc)
        expires_str = (
            now + timedelta(days=365)
        ).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

        signed = {
            "vin": vin,
            "primary_ecu_serial": primary_ecu_serial,
            "expires": expires_str,
            "ecu_version": vvm_version
        }

        signed["keyid"] = vvm_keyid
        sig = sign_block_ed25519(ed_private_key, signed)

        vvm_obj = {
            "signatures": [
                {
                    "keyid": vvm_keyid,
                    "sig": sig,
                }
            ],
            "signed": signed,
        }

        VVM_JSON_PATH = Path("vvm.json")

        VVM_JSON_PATH.write_text(
            json.dumps(vvm_obj, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"vvm.json 업데이트 완료: {VVM_JSON_PATH}")


    
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
