# Primary_ECU/Prime_ECU.py
import json, ssl, time
import paho.mqtt.client as mqtt

from ecu import (
    Updater,
    Storage,
    Transport,
    Verifier,
    Installer,
    Reporter,
)

BROKER = "192.168.182.9"
PORT = 8883

TOPIC_NOTIFY_VERSION     = "primary/version"     # VVM 전송
TOPIC_DIRECTOR_TIMESTAMP = "director/timestamp"  # timestamp 메타 수신
TOPIC_DIRECTOR_SNAPSHOT  = "director/snapshot"   # snapshot 메타 수신
TOPIC_DIRECTOR_TARGETS   = "director/targets"    # targets_per_vehicle 메타 수신
TOPIC_REPORT             = "primary/report"      # 상태 보고

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

    def _configure_tls(self, client, ca_cert, client_cert, client_key):
        client.tls_set(ca_certs=ca_cert, certfile=client_cert, keyfile=client_key, tls_version=ssl.PROTOCOL_TLSv1_2)
        client.tls_insecure_set(True)

    def on_connect(self, client, userdata, flags, rc, properties=None):
        print(f"[Prime ECU] Connected: {rc}")
        client.subscribe(TOPIC_DIRECTOR_TIMESTAMP, qos=1)
        client.subscribe(TOPIC_DIRECTOR_SNAPSHOT, qos=1)
        client.subscribe(TOPIC_DIRECTOR_TARGETS, qos=1)

    def on_message(self, client, userdata, msg):
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

if __name__ == "__main__":
    handler = PrimeEcuHandler(BROKER, PORT)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        handler.client.loop_stop()
