# Primary_ECU/Prime_ECU.py
import json, ssl, time
import paho.mqtt.client as mqtt

from ecu.updater import Updater, UpdateRequest
from ecu.storage import Storage
from ecu.transport import Transport
from ecu.verifier import Verifier
from ecu.installer import Installer
from manage_meta import generate_vvm  # 기존 그대로 사용

BROKER = "192.168.35.202"
PORT = 8883

TOPIC_NOTIFY_VERSION = "primary/version"
TOPIC_UPDATE_META    = "director/updateMeta"   # 디렉터가 메타/이미지 url을 알려주는 토픽 예시
TOPIC_REPORT         = "primary/report"

CA_CERT     = "./utils/certs/ca.crt"
CLIENT_CERT = "./utils/certs/mqtt_client.crt"
CLIENT_KEY  = "./utils/certs/mqtt_client.key"

class Reporter:
    def __init__(self, client: mqtt.Client): self.client = client
    def report(self, status: str, payload: dict):
        self.client.publish(TOPIC_REPORT, json.dumps({"status": status, **payload}), qos=1)

class PrimeEcuHandler:
    def __init__(self, broker, port):
        self.client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        self._configure_tls(self.client, CA_CERT, CLIENT_CERT, CLIENT_KEY)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.connect(broker, port, 60)
        self.client.loop_start()

        # Updater 구성요소
        self.storage  = Storage()                    # ~/.primary_ecu
        self.transport= Transport()
        self.verifier = Verifier()
        self.installer= Installer(self.storage)
        self.reporter = Reporter(self.client)
        self.updater  = Updater(self.storage, self.transport, self.verifier, self.installer, self.reporter)

        # VVM 생성 및 전송(기존 로직 유지)
        generate_vvm()
        with open("./vehicle_version_manifest.json","r",encoding="utf-8") as f:
            vvm = json.load(f)
        self.client.publish(TOPIC_NOTIFY_VERSION, json.dumps(vvm, ensure_ascii=False).encode("utf-8"), qos=0)

    def on_connect(self, client, userdata, flags, rc, properties=None):
        print(f"[Prime ECU] Connected: {rc}")
        client.subscribe(TOPIC_UPDATE_META, qos=1)

    def on_message(self, client, userdata, msg):
        if msg.topic == TOPIC_UPDATE_META:
            # 디렉터가 내려주는 메시지 예시 형식:
            # {
            #   "version": "1.2.3",
            #   "meta_url": "http://.../meta_1.2.3.json",
            #   "image_url": "http://.../image_1.2.3.bin",
            #   "expected_sha256": "abcd..."
            # }
            data = json.loads(msg.payload.decode("utf-8"))
            req = UpdateRequest(
                version=data["version"],
                meta_url=data["meta_url"],
                image_url=data["image_url"],
                expected_sha256=data["expected_sha256"],
                extra=data.get("extra")
            )
            self.updater.run(req)

    def _configure_tls(self, client, ca_cert, client_cert, client_key):
        client.tls_set(ca_certs=ca_cert, certfile=client_cert, keyfile=client_key, tls_version=ssl.PROTOCOL_TLSv1_2)
        client.tls_insecure_set(True)

if __name__ == "__main__":
    handler = PrimeEcuHandler(BROKER, PORT)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        handler.client.loop_stop()
