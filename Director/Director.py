import os
import time
import json
import ssl
import paho.mqtt.client as mqtt
import base64
from ecdsa import VerifyingKey, BadSignatureError
from ecdsa import ed25519  # Ed25519 사용

from version_compare import select_updates_for_vehicle

# (임시) 공개키 매핑
PRIMARY_KEY_MAP = {
    "primary_ecu_key_identifier": "./keys/primary_ecu_pub.pem"
}

def canonical_json_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def verify_vvm_signature(vvm: Dict[str, Any]) -> bool:
    sigs = vvm.get("signatures") or []
    if not sigs:
        return False

    signed_body = vvm.get("signed")
    if not isinstance(signed_body, dict):
        return False

    message = canonical_json_bytes(signed_body)

    for s in sigs:
        keyid = s.get("keyid")
        sig_b64 = s.get("sig")
        if not keyid or not sig_b64:
            continue

        pub_path = PRIMARY_KEY_MAP.get(keyid)
        if not pub_path or not os.path.exists(pub_path):
            continue

        try:
            with open(pub_path, "rb") as f:
                vk = VerifyingKey.from_pem(f.read(), hashfunc=None)
                sig = base64.b64decode(sig_b64)
                vk.verify(sig, message, sigdecode=ed25519.sigdecode)
                return True
        except BadSignatureError:
            pass
        except Exception as e:
            print(f"[ERR] VVM signature verify error: {e}")

    return False

class DirectorRepoHandler:
    def __init__(self, broker, port):
        self.MQTT_BROKER = broker
        self.MQTT_PORT = port

        self.update_meta_topic = "director/updateMeta"
        self.notify_version_topic = "primary/version"

        self.update_json = "../data/update.json"
        self.target_meta = "../data/target_new.json"

        self.ca_cert = "./utils/certs/ca.crt"
        self.client_cert = "./utils/certs/mqtt_client.crt"
        self.client_key = "./utils/certs/mqtt_client.key"

        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        configure_tls(self.client, self.ca_cert, self.client_cert, self.client_key)

        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

        self.json_handler = JsonHandler()

    def connect_mqtt(self):
        self.client.connect(self.MQTT_BROKER, self.MQTT_PORT, 60)

    def loop_mqtt(self):
        self.client.loop_start()

    def on_connect(self, client, userdata, flags, rc, properties=None):
        print(f"[DirectorRepo] Connected: {rc}")
        client.subscribe(self.notify_version_topic)

    def on_message(self, client, userdata, msg):
        payload = json.loads(msg.payload.decode())

        if msg.topic != self.notify_version_topic:
            return

        print("\nReceive Manifest from Gateway\n")

        # 0) VVM 최상위 서명 검증
        if not verify_vvm_signature(payload):
            print("[ERR] VVM signature verification failed → drop")
            return
        print("[OK] VVM signature verified")

        # 1) 매니페스트 수신
        vehicle_manifest = payload

        # 2) 전역 targets 로드 (지금은 1.targets.json 고정)
        try:
            with open("./targets.json", "r", encoding="utf-8") as f:
                global_targets = json.load(f)
        except Exception as e:
            print(f"[ERR] failed to load global targets: {e}")
            return

        # 3) per-vehicle targets 생성
        try:
            sel = select_updates_for_vehicle(vehicle_manifest, global_targets)
            per_vehicle_doc = sel["targets_doc"]
            debug_info = sel.get("debug", {})

            # 결과 저장
            os.makedirs("./out", exist_ok=True)
            with open("./out/per_vehicle.targets.json", "w", encoding="utf-8") as f:
                json.dump(per_vehicle_doc, f, ensure_ascii=False, indent=2)

            print(f"[OK] built per-vehicle targets → ./out/per_vehicle.targets.json")
            if debug_info:
                print(f"  - selected_count={debug_info.get('selected_count')}, reasons={debug_info.get('reasons')}")
        except Exception as e:
            print(f"[ERR] failed to build per-vehicle targets: {e}")
            return

        # 4) publish
        try:
            client.publish(
                self.update_meta_topic,
                json.dumps(per_vehicle_doc, ensure_ascii=False),
                qos=1
            )
            print("\nPublish per-vehicle targets metadata\n")
        except Exception as e:
            print(f"[ERR] failed to publish: {e}")


def configure_tls(client, ca_cert, client_cert, client_key):
    client.tls_set(
        ca_certs= ca_cert,
        certfile= client_cert,
        keyfile= client_key,
        tls_version=ssl.PROTOCOL_TLSv1_2
    )
    client.tls_insecure_set(False)

if __name__ == "__main__":
    handler = DirectorRepoHandler("192.168.86.37", 8883)
    handler.connect_mqtt()
    handler.loop_mqtt()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        handler.client.loop_stop()
