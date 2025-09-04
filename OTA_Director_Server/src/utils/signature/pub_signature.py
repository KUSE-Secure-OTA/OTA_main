import paho.mqtt.client as mqtt
import base64
import time
import json
import os
import hashlib
from ecdsa import SigningKey, NIST384p
from datetime import datetime, timezone

KEYS_DIR = "./utils/signature/private_keys"  # 다중 서명 키 폴더

def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        print("Connected OK")
    else:
        print("Error: Connection fail, Return code =", reason_code)

def on_disconnect(client, userdata, flags, rc=0):
    print(str(rc))

def on_publish(client, userdata, mid):
    print("In on_publish callback mid =", mid)

def get_current_utc_time():
    return datetime.now(timezone.utc).isoformat()

def make_payload_with_signatures(data):
    # timestamp 추가
    data["timestamp"] = get_current_utc_time()

    # signed 부분 (원본 payload)
    signed = data.copy()
    signatures = []

    # 각 PEM 키로 서명
    for filename in os.listdir(KEYS_DIR):
        if not filename.endswith(".pem"):
            continue
        
        key_path = os.path.join(KEYS_DIR, filename)
        sk = SigningKey.from_pem(open(key_path, "r").read())
        message_bytes = json.dumps(signed, sort_keys=True, separators=(',', ':')).encode()
        sig = sk.sign(message_bytes)
        sig_b64 = base64.b64encode(sig).decode()

        # keyid는 SHA256으로 PEM 파일 해시
        with open(key_path, "rb") as f:
            key_bytes = f.read()
            keyid = hashlib.sha256(key_bytes).hexdigest()
        
        signatures.append({
            "keyid": keyid,
            "sig": sig_b64
        })

    payload = {
        "signed": signed,
        "signatures": signatures
    }

    return json.dumps(payload, indent=4)

if __name__ == "__main__":
    client = mqtt.Client(protocol=mqtt.MQTTv5)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish

    # JSON 파일 불러오기
    with open("./update.json", "r", encoding="utf-8") as f:
        update_data = json.load(f)

    json_message = make_payload_with_signatures(update_data)

    # Publish MQTT
    while True:
        client.connect("192.168.86.30", 1883)
        client.loop_start()
        try:
            print("Publishing:", json_message)
            client.publish("OTA", json_message, qos=2, retain=False)
            print("Success Publish")
            time.sleep(2)
        except KeyboardInterrupt:
            print("Terminating...")
            break
        finally:
            client.loop_stop()
            client.disconnect()