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
from manage_meta import generate_vvm  # VVM 생성 함수 (파일: vehicle_version_manifest.json)

BROKER = "192.168.35.202"
PORT = 8883

TOPIC_NOTIFY_VERSION = "primary/version"     # VVM 전송 토픽 (업데이트 전/후 동일)
TOPIC_UPDATE_META    = "director/updateMeta" # Director → ECU (업데이트 지시)
TOPIC_REPORT         = "primary/report"      # ECU → Director (상태/에러 보고)

CA_CERT     = "./utils/certs/ca.crt"
CLIENT_CERT = "./utils/certs/mqtt_client.crt"
CLIENT_KEY  = "./utils/certs/mqtt_client.key"


class PrimeEcuHandler:
    def __init__(self, broker: str, port: int):
        # MQTT 클라이언트 설정
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

        # ── ① 부팅 시: "기존에 있던 VVM"을 전송 ───────────────────────────────
        # 파일이 없으면 최소한의 환경을 보장한 뒤 한 번 생성합니다.
        os.makedirs("./version_report", exist_ok=True)
        self._ensure_vvm_exists()
        vvm = self._load_vvm()
        self._publish_vvm(vvm)

    # ── MQTT 콜백 ────────────────────────────────────────────────────────────
    def on_connect(self, client, userdata, flags, rc, properties=None):
        print(f"[Prime ECU] Connected: rc={rc}")
        client.subscribe(TOPIC_UPDATE_META, qos=1)

    def on_message(self, client, userdata, msg):
        if msg.topic != TOPIC_UPDATE_META:
            return

        payload = json.loads(msg.payload.decode("utf-8"))
        # 예시 페이로드:
        # {
        #   "version": "1.2.3",
        #   "meta_url": "http://.../meta.json",
        #   "image_url": "http://.../image_1.2.3.bin",
        #   "expected_sha256": "abcd..."
        # }
        req = UpdateRequest(
            version=payload["version"],
            meta_url=payload["meta_url"],
            image_url=payload["image_url"],
            expected_sha256=payload["expected_sha256"],
            extra=payload.get("extra"),
        )

        # ② OTA 수행 (성공 시 True)
        ok = self.updater.run(req)

        # ③ 성공하면 "새 VVM"을 다시 생성하여 전송
        if ok:
            generate_vvm()         # 새 VVM 생성 (vehicle_version_manifest.json 갱신)
            vvm = self._load_vvm()
            self._publish_vvm(vvm)
        # 실패 시에는 updater가 Reporter를 통해 error 이벤트를 이미 발행합니다.

    # ── TLS 설정 ─────────────────────────────────────────────────────────────
    def _configure_tls(self, client, ca_cert, client_cert, client_key):
        client.tls_set(ca_certs=ca_cert, certfile=client_cert, keyfile=client_key, tls_version=ssl.PROTOCOL_TLSv1_2)
        client.tls_insecure_set(True)

    # ── VVM 유틸 ─────────────────────────────────────────────────────────────
    def _ensure_vvm_exists(self):
        """
        '기존에 있던 VVM'을 보내려 할 때 파일이 없으면 1회 생성합니다.
        (version_report 디렉터리 내용 기준으로 생성)
        """
        if not os.path.exists("./vehicle_version_manifest.json"):
            generate_vvm()

    def _load_vvm(self) -> dict:
        with open("./vehicle_version_manifest.json", "r", encoding="utf-8") as f:
            return json.load(f)

    def _publish_vvm(self, vvm_payload: dict):
        # 요구사항대로 추가 래핑 없이 '기존 VVM/새 VVM' 본문 그대로 발행
        self.client.publish(TOPIC_NOTIFY_VERSION, json.dumps(vvm_payload, ensure_ascii=False), qos=1)


if __name__ == "__main__":
    handler = PrimeEcuHandler(BROKER, PORT)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        handler.client.loop_stop()
