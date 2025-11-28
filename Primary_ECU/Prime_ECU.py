# Primary_ECU/Prime_ECU.py
import json, ssl, time, tarfile, os, shutil, binascii, hashlib
import paho.mqtt.client as mqtt
import requests
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urljoin
from utils.fastcdc_chunking import join_all, load_image_from_oci, run_container

try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except ImportError:
    from backports.zoneinfo import ZoneInfo  # backports 패키지 필요
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ecu import (
    Updater,
    Storage,
    Transport,
    Verifier,
    Installer,
    Reporter,
)

BROKER = "192.168.35.202"
PORT = 8883

TOPIC_NOTIFY_VERSION     = "primary/version"     # VVM 전송
TOPIC_DIRECTOR_TIMESTAMP = "director/timestamp"  # timestamp 메타 수신
TOPIC_DIRECTOR_SNAPSHOT  = "director/snapshot"   # snapshot 메타 수신
TOPIC_DIRECTOR_TARGETS   = "director/targets"    # targets_per_vehicle 메타 수신
TOPIC_REPORT             = "primary/report"      # 상태 보고
TOPIC_REQUEST_UPDATE     = "primary/request"  # 업데이트 요청
TOPIC_IMAGE_META         = "image/metaData"   # 이미지 메타 수신

CA_CERT     = "./utils/certs/ca.crt"
CLIENT_CERT = "./utils/certs/client.crt"
CLIENT_KEY  = "./utils/certs/client.key"

class PrimeEcuHandler:
    def __init__(self, broker, port):
        self.client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        self._configure_tls(self.client, CA_CERT, CLIENT_CERT, CLIENT_KEY)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.connect(broker, port, 60)
        self.client.loop_start()

        # Updater 구성요소
        self.storage  = Storage()
        self.transport= Transport()
        self.verifier = Verifier()
        self.installer= Installer(self.storage)
        self.reporter = Reporter(self.client, TOPIC_REPORT)
        self.updater  = Updater(self.storage, self.transport, self.verifier, self.installer, self.reporter)

        self.meta_buffer = {
            "timestamp": None,
            "snapshot":  None,
            "targets":   None,
        }

        # VVM 전송
        with open("./vvm.json","r",encoding="utf-8") as f:
            vvm = json.load(f)
        self.client.publish(TOPIC_NOTIFY_VERSION, json.dumps(vvm, ensure_ascii=False).encode("utf-8"), qos=0)
        
        #=========================================================================================================
        # Director 메타데이터 검증
        #=========================================================================================================

        # self.client.publish(TOPIC_REQUEST_UPDATE, json.dumps({}, ensure_ascii=False).encode("utf-8"), qos=0)

    def _configure_tls(self, client, ca_cert, client_cert, client_key):
        client.tls_set(ca_certs=ca_cert, certfile=client_cert, keyfile=client_key, tls_version=ssl.PROTOCOL_TLSv1_2)
        client.tls_insecure_set(True)

    def on_connect(self, client, userdata, flags, rc, properties=None):
        print(f"[Prime ECU] Connected: {rc}")
        client.subscribe(TOPIC_DIRECTOR_TIMESTAMP, qos=1)
        client.subscribe(TOPIC_DIRECTOR_SNAPSHOT, qos=1)
        client.subscribe(TOPIC_DIRECTOR_TARGETS, qos=1)
        client.subscribe(TOPIC_IMAGE_META, qos=1)

    def handle_meta_json(self, meta: dict):
        

        base_url = meta.get("url")
        if not base_url:
            raise ValueError("Meta JSON missing 'url' field")
        
        chunks = meta.get("chunks")
        if chunks is None:
            raise ValueError("Meta JSON missing 'chunks' field")
        
        self.download_manifests(base_url)

        self.download_chunks(base_url, chunks)

    def canonical_json_bytes(self, obj: Any) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def parse_timestamp_datetime(self, dt_str: str) -> datetime:
        """
        TUF 스타일의 expires 문자열(예: '2025-11-27T12:34:56Z')을
        timezone-aware datetime(UTC)로 변환.
        """
        # 뒤에 'Z'가 붙어 있으면 +00:00 으로 바꿔서 fromisoformat에 먹인다.
        if dt_str.endswith("Z"):
            dt_str = dt_str[:-1] + "+00:00"
        return datetime.fromisoformat(dt_str)
    
    def load_root_key_by_keyid(self, root_path: str, keyid: str) -> Dict[str, Any]:
        """
        root.json에서 keyid로 key 객체를 찾아 반환.
        """
        with open(root_path, "r", encoding="utf-8") as f:
            root_doc = json.load(f)

        signed = root_doc["signed"]
        keys = signed["keys"]  # { keyid: keyobj }

        if keyid not in keys:
            raise KeyError(f"[!] root.json에 keyid={keyid} 가 존재하지 않습니다.")

        return keys[keyid]
    
    def ed25519_verify_hex(self, pub_hex: str, data: bytes, sig_hex: str) -> None:
        """
        pub_hex(32바이트 Ed25519 공개키 hex)와 sig_hex(서명 hex)를 이용해 검증.
        검증 실패 시 InvalidSignature 예외 발생.
        """
        pub_bytes = binascii.unhexlify(pub_hex)
        sig_bytes = binascii.unhexlify(sig_hex)

        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, data)  # 예외 없으면 검증 성공

    def verity_timestamp(self, signed_obj):
        # 5) 만료 시간(expires) 검증
        expires_str = signed_obj.get("expires")
        if not expires_str:
            raise RuntimeError("[!] timestamp.signed.expires 필드가 없습니다.")

        expires_dt = self.parse_timestamp_datetime(expires_str)

        # 보통 TUF 메타데이터는 UTC 기준이므로 UTC now 사용
        now = datetime.now(timezone.utc)

        if now >= expires_dt:
            print(
                f"[!] timestamp 메타데이터 만료됨: "
                f"expires={expires_dt.isoformat()}, now={now.isoformat()}"
            )
            return False

        print("[*] timestamp 서명 및 만료 시간 검증 성공 (유효 기간 내)")
        return True

    
    def verify_metadata(self, meta: dict,
                        s_hash: Optional[str] = None, 
                        target_ver: Optional[int] = None,
                        snapshot_raw: Optional[bytes] = None) -> Tuple[bool, Optional[Any]]:
        # Verify a signature
        signatures = meta.get("signatures", [])
        if not signatures:
            raise RuntimeError("[!] timestamp.json에 signatures가 없습니다.")
        
        sig_entry = signatures[0]
        keyid = sig_entry["keyid"]
        sig_hex = sig_entry["sig"]

        keyobj = self.load_root_key_by_keyid("./meta/root.json", keyid)

        if keyobj.get("keytype") != "ed25519":
            raise RuntimeError(
                f"[!] keyid={keyid} 의 keytype이 ed25519가 아닙니다: {keyobj.get('keytype')}"
            )
        
        pub_hex = keyobj.get("keyval", {}).get("public")
        if not pub_hex:
            raise RuntimeError(f"[!] keyid={keyid} 의 keyval.public 이 비어 있습니다.")
        
        signed_obj = meta["signed"]
        payload = self.canonical_json_bytes(signed_obj)

        try:
            self.ed25519_verify_hex(pub_hex, payload, sig_hex)

        except Exception as e:
            print(f"[!] timestamp 서명 검증 실패: {e}")
            return False, None
        
        meta_type = signed_obj.get("_type")

        if meta_type == "timestamp":
            # expires 검증
            if not self.verity_timestamp(signed_obj):
                print("[FAIL] Timestamp is not correct")
                return False, None

            signed_meta = signed_obj.get("meta", {})
            try:
                s_hash_val = signed_meta["snapshot.json"]["hashes"]["sha256"]
            except KeyError:
                print("[FAIL] timestamp.meta에 snapshot.json 해시가 없습니다.")
                return False, None

            return True, s_hash_val
        
        elif meta_type == "snapshot":
            if s_hash is None:
                print("[FAIL] snapshot 검증에 필요한 s_hash가 없습니다.")
                return False, None

            # meta 전체를 canonical JSON으로 해시 (또는 정책에 맞게 signed_obj만 해시)
            #payload_all = self.canonical_json_bytes(meta)
            sha = hashlib.sha256(snapshot_raw).hexdigest()

            if sha != s_hash:
                print("[FAIL] Snapshot hash mismatch")
                print(f"expected: {s_hash}")
                print(f"actual  : {sha}")
                return False, None

            signed_meta = signed_obj.get("meta", {})
            try:
                target_ver_val = signed_meta["targets.json"]["version"]
            except KeyError:
                print("[FAIL] snapshot.meta에 targets.json version이 없습니다.")
                return False, None

            return True, target_ver_val

        elif meta_type == "targets":
            # target_ver를 가지고 버전 일관성 체크를 하고 싶으면 여기서 추가
            targets_val = signed_obj.get("targets")
            return True, targets_val

        # 그 외 타입은 단순히 서명만 성공한 것으로 처리
        return True, None


    def on_message(self, client, userdata, msg):
        if msg.topic == TOPIC_IMAGE_META:
            try:
                timestamp_meta = json.loads(msg.payload.decode("utf-8"))
            except Exception as e:
                print(f"[Prime ECU] invalid JSON on {msg.topic}: {e}")
                return

            print("[Prime ECU] received image metadata\n")

            base_url = timestamp_meta["url"]

            ok, s_hash = self.verify_metadata(timestamp_meta)
            if not ok or s_hash is None:
                print("[FAIL] Timestamp metadata is not correct")
                return

            url = urljoin(base_url.rstrip('/') + "/", "meta/snapshot.json")
            print(f"Downloading manifests from {url}")
            response = requests.get(url, verify=False)
            response.raise_for_status()

            raw_snapshot_bytes = response.content 
            snapshot_meta = response.json()
            print("[Prime ECU] received Snapshot metadata\n")

            ok, target_version = self.verify_metadata(snapshot_meta, s_hash, snapshot_raw=raw_snapshot_bytes)
            if not ok or target_version is None:
                print("[FAIL] Snapshot metadata is not correct")
                return

            url = urljoin(base_url.rstrip('/') + "/", "meta/targets.json")
            print(f"Downloading manifests from {url}")
            response = requests.get(url, verify=False)
            response.raise_for_status()

            targets_meta = response.json()
            print("[Prime ECU] received Target metadata\n")
            ok, targets = self.verify_metadata(targets_meta, target_version)
            if not ok:
                print("[FAIL] Targets metadata is not correct")
                return

            print("[OK] All metadata verified successfully")
            print(targets)
            # 이후 chunk 다운로드, 업데이트 시작 등...
            return


            
            # for d in ["./downloads", "./downloads/chunk_storage", "./downloads/manifests", "./downloads/reassembled_oci", "./downloads/reassembled_oci/merged_rootfs"]:
            #     os.makedirs(d, exist_ok=True)
            # self.handle_meta_json(image_meta)

            # with tarfile.open("./downloads/manifests.tar.gz", "r:gz") as tar:
            #         tar.extractall("./downloads")
            # os.remove("./downloads/manifests.tar.gz")

            # join_metrics, join_time = join_all("./downloads/manifests", "./downloads/reassembled_oci", "./downloads/chunk_storage")
            # load_image_from_oci("./downloads/reassembled_oci")
            # run_container()
            # self.updater.start_update(image_meta)
            return
        else:
            try:
                meta = json.loads(msg.payload.decode("utf-8"))
            except Exception as e:
                print(f"[Prime ECU] invalid JSON on {msg.topic}: {e}")
                return
            
            role = None
            s_hash = None
            target_version = None
            targets = None

            if msg.topic == TOPIC_DIRECTOR_TIMESTAMP:
                role = "timestamp"
                print("[Prime ECU] received Director Timestamp metadata\n")

                # ok, s_hash = self.verify_metadata(meta)
                # if not ok or s_hash is None:
                #     print("[FAIL] Timestamp metadata is not correct")
                #     return

            elif msg.topic == TOPIC_DIRECTOR_SNAPSHOT:
                role = "snapshot"
                print("[Prime ECU] received Director Snapshot metadata\n")

                # ok, target_version = self.verify_metadata(meta, s_hash, snapshot_raw=msg.payload)
                # if not ok or s_hash is None:
                #     print("[FAIL] Timestamp metadata is not correct")
                #     return
            elif msg.topic == TOPIC_DIRECTOR_TARGETS:
                role = "targets"
                print("[Prime ECU] received Director Targets metadata\n")

                # ok, targets = self.verify_metadata(meta, target_version)
                # if not ok or s_hash is None:
                #     print("[FAIL] Timestamp metadata is not correct")
                #     return
                
                # self.client.publish(TOPIC_REQUEST_UPDATE, json.dumps({}, ensure_ascii=False).encode("utf-8"), qos=0)


            if role is not None:
                try:
                    meta = json.loads(msg.payload.decode("utf-8"))
                except Exception as e:
                    print(f"[Prime ECU] invalid JSON on {msg.topic}: {e}")
                    return

                self.meta_buffer[role] = meta
                print(f"[Prime ECU] received {role} metadata")

                # Director 메타데이터 모두 들어왔는지 확인
                if all(self.meta_buffer[r] is not None for r in ("timestamp", "snapshot", "targets")):
                    self._on_all_director_meta_received()
    
    def _on_all_director_meta_received(self):
        ts = self.meta_buffer["timestamp"]
        sn = self.meta_buffer["snapshot"]
        tg = self.meta_buffer["targets"]

        print("[Prime ECU] all director metadata received, start verification")

        vr = self.verifier.verify_director_chain(ts, sn, tg)

        if not vr.ok:
            print(f"[Prime ECU] director metadata verify FAILED: {vr.reason}")
            try:
                self.reporter.report("director_meta_verify_failed", {
                    "reason": vr.reason,
                })
            except Exception as e:
                print(f"[Prime ECU] report failed: {e}")
        else:
            print("[Prime ECU] director metadata verify OK")
            try:
                self.reporter.report("director_meta_verify_ok", {})
            except Exception as e:
                print(f"[Prime ECU] report failed: {e}")

        # 다음 업데이트를 위해 버퍼 초기화
        self.meta_buffer = {k: None for k in self.meta_buffer}

    # def download_manifests(self, base_url: str) -> str:
    #     url = urljoin(base_url.rstrip('/') + "/", "manifests")
    #     print(f"Downloading manifests from {url}")
    #     response = requests.get(url, verify=False)
    #     response.raise_for_status()

    #     out_path = "./downloads/manifests.tar.gz"
    #     with open(out_path, "wb") as f:
    #         f.write(response.content)
    #     print(f"Manifests downloaded to {out_path}")
    #     return out_path
    
    # def download_chunks(self, base_url: str, chunks: list):
    #     for i, name in enumerate(chunks, start=1):
    #         url = urljoin(base_url.rstrip('/') + "/", f"chunks/{name}")
    #         out_path = f"./downloads/chunk_storage/{name}"

    #         try:
    #             with requests.get(url, stream=True, verify=False) as response:
    #                 response.raise_for_status()
    #                 with open(out_path, "wb") as f:
    #                     for chunk in response.iter_content(chunk_size=8192):
    #                         if chunk:
    #                             f.write(chunk)
    #             print(f"[OK] saved chunk -> {out_path}")
    #         except Exception as e:
    #             print(f"[FAIL] failed to download chunk {name} from {url}: {e}")
    
    # def handle_meta_json(self, meta: dict):
    #     base_url = meta.get("url")
    #     if not base_url:
    #         raise ValueError("Meta JSON missing 'url' field")
        
    #     chunks = meta.get("chunks")
    #     if chunks is None:
    #         raise ValueError("Meta JSON missing 'chunks' field")
        
    #     self.download_manifests(base_url)

    #     self.download_chunks(base_url, chunks)

if __name__ == "__main__":
    handler = PrimeEcuHandler(BROKER, PORT)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        handler.client.loop_stop()
