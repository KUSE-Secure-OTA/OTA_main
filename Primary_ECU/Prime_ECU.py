import os
import json, ssl, time
import paho.mqtt.client as mqtt

from ecu import (
    Updater,
    UpdateRequest,
    Storage,
    Transport,
    Verifier,
    Installer,
    Reporter,
)
from manage_meta import generate_vvm

BROKER = "192.168.35.202"
PORT = 8883

TOPIC_NOTIFY_VERSION = "primary/version"
TOPIC_UPDATE_META    = "director/updateMeta"
TOPIC_REPORT         = "primary/report"

CA_CERT     = "./utils/certs/ca.crt"
CLIENT_CERT = "./utils/certs/mqtt_client.crt"
CLIENT_KEY  = "./utils/certs/mqtt_client.key"


class PrimeEcuHandler:
    def __init__(self, broker: str, port: int):
        # MQTT 클라이언트 생성/설정
        self.client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        self._configure_tls(self.client, CA_CERT, CLIENT_CERT, CLIENT_KEY)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.connect(broker, port, 60)
        self.client.loop_start()

        # OTA 구성요소
        self.storage   = Storage()              # ~/.primary_ecu
        self.transport = Transport()
        self.verifier  = Verifier()
        self.installer = Installer(self.storage)
        self.reporter  = Reporter(self.client, TOPIC_REPORT)
        self.updater   = Updater(
            storage=self.storage,
            transport=self.transport,
            verifier=self.verifier,
            installer=self.installer,
            reporter=self.reporter,
        )

        # VVM 생성 및 통지
        os.makedirs("./version_report", exist_ok=True)  # ← 버전 리포트 디렉터리 보장
        generate_vvm()
        with open("./vehicle_version_manifest.json", "r", encoding="utf-8") as f:
            vvm = json.load(f)
        self.client.publish(TOPIC_NOTIFY_VERSION, json.dumps(vvm, ensure_ascii=False), qos=0)

    # ── MQTT 콜백 ────────────────────────────────────────────────────────────
    def on_connect(self, client, userdata, flags, rc, properties=None):
        print(f"[Prime ECU] Connected: rc={rc}")
        client.subscribe(TOPIC_UPDATE_META, qos=1)

    def on_message(self, client, userdata, msg):
        if msg.topic != TOPIC_UPDATE_META:
            return
        payload = json.loads(msg.payload.decode("utf-8"))
        req = UpdateRequest(
            version=payload["version"],
            meta_url=payload["meta_url"],
            image_url=payload["image_url"],
            expected_sha256=payload["expected_sha256"],
            extra=payload.get("extra"),
        )
        self.updater.run(req)

    # ── TLS 설정 ─────────────────────────────────────────────────────────────
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
