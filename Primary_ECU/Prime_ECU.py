# Primary_ECU/Prime_ECU.py
import json, ssl, time, tarfile, os, shutil
import paho.mqtt.client as mqtt
import requests
from urllib.parse import urljoin
from utils.fastcdc_chunking import join_all, load_image_from_oci, run_container

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
        self.client.publish(TOPIC_REQUEST_UPDATE, json.dumps({}, ensure_ascii=False).encode("utf-8"), qos=0)

    def _configure_tls(self, client, ca_cert, client_cert, client_key):
        client.tls_set(ca_certs=ca_cert, certfile=client_cert, keyfile=client_key, tls_version=ssl.PROTOCOL_TLSv1_2)
        client.tls_insecure_set(True)

    def on_connect(self, client, userdata, flags, rc, properties=None):
        print(f"[Prime ECU] Connected: {rc}")
        client.subscribe(TOPIC_DIRECTOR_TIMESTAMP, qos=1)
        client.subscribe(TOPIC_DIRECTOR_SNAPSHOT, qos=1)
        client.subscribe(TOPIC_DIRECTOR_TARGETS, qos=1)
        client.subscribe(TOPIC_IMAGE_META, qos=1)

    def on_message(self, client, userdata, msg):
        if msg.topic == TOPIC_IMAGE_META:
            try:
                image_meta = json.loads(msg.payload.decode("utf-8"))
            except Exception as e:
                print(f"[Prime ECU] invalid JSON on {msg.topic}: {e}")
                return

            print("[Prime ECU] received image metadata, start update process")
            
            for d in ["./downloads", "./downloads/chunk_storage", "./downloads/manifests", "./downloads/reassembled_oci", "./downloads/reassembled_oci/merged_rootfs"]:
                os.makedirs(d, exist_ok=True)
            self.handle_meta_json(image_meta)

            with tarfile.open("./downloads/manifests.tar.gz", "r:gz") as tar:
                    tar.extractall("./downloads")
            os.remove("./downloads/manifests.tar.gz")

            join_metrics, join_time = join_all("./downloads/manifests", "./downloads/reassembled_oci", "./downloads/chunk_storage")
            load_image_from_oci("./downloads/reassembled_oci")
            run_container()
            # self.updater.start_update(image_meta)
            return
        else:
            role = None
            if msg.topic == TOPIC_DIRECTOR_TIMESTAMP:
                role = "timestamp"
            elif msg.topic == TOPIC_DIRECTOR_SNAPSHOT:
                role = "snapshot"
            elif msg.topic == TOPIC_DIRECTOR_TARGETS:
                role = "targets"

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

    def download_manifests(self, base_url: str) -> str:
        url = urljoin(base_url.rstrip('/') + "/", "manifests")
        print(f"Downloading manifests from {url}")
        response = requests.get(url, verify=False)
        response.raise_for_status()

        out_path = "./downloads/manifests.tar.gz"
        with open(out_path, "wb") as f:
            f.write(response.content)
        print(f"Manifests downloaded to {out_path}")
        return out_path
    
    def download_chunks(self, base_url: str, chunks: list):
        for i, name in enumerate(chunks, start=1):
            url = urljoin(base_url.rstrip('/') + "/", f"chunks/{name}")
            out_path = f"./downloads/chunk_storage/{name}"

            try:
                with requests.get(url, stream=True, verify=False) as response:
                    response.raise_for_status()
                    with open(out_path, "wb") as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                print(f"[OK] saved chunk -> {out_path}")
            except Exception as e:
                print(f"[FAIL] failed to download chunk {name} from {url}: {e}")
    
    def handle_meta_json(self, meta: dict):
        base_url = meta.get("url")
        if not base_url:
            raise ValueError("Meta JSON missing 'url' field")
        
        chunks = meta.get("chunks")
        if chunks is None:
            raise ValueError("Meta JSON missing 'chunks' field")
        
        self.download_manifests(base_url)

        self.download_chunks(base_url, chunks)

if __name__ == "__main__":
    handler = PrimeEcuHandler(BROKER, PORT)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        handler.client.loop_stop()
