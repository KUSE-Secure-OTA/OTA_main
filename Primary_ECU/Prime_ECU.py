import paho.mqtt.client as mqtt
import json
import ssl
import base64
import time
from manage_meta import generate_vvm, read_root, verify_multi_signature
from utils.signature.pub_signature import make_payload_with_signature

brokerIp = "172.16.1.90"
port = 8883

class PrimeEcuHandler:
    def __init__(self, broker, port):
        self.MQTT_BROKER = broker
        self.MQTT_PORT = port

        self.notify_version_topic = "primary/version"
        self.update_meta_topic = "director/updateMeta"
        self.request_meta_topic = "primary/requestMeta"
        self.request_update_topic = "primary/requestUpdate"

        self.ca_cert = "./utils/certs/ca.crt"
        self.client_cert = "./utils/certs/mqtt_client.crt"
        self.client_key = "./utils/certs/mqtt_client.key"

        self.key_info = {}

        self.client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        self.configure_tls(self.client, self.ca_cert, self.client_cert, self.client_key)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

        self.connect_mqtt()
        self.loop_mqtt()

        # Make a VVM(Vehicle Version Manifest)
        generate_vvm()

        # Send VVM to Director Repo
        try:
            with open("./vehicle_version_manifest.json", "r", encoding="utf-8") as f:
            #with open("./vvm.json", "r", encoding="utf-8") as f:
                data = json.load(f)
            print(f"[Prime ECU] VVM is ready")
        except Exception as e:
            print(f"[Prime ECU / Error] Version List load Error:    {e}")

        # vvm_payload = make_payload_with_signature(data)
        if data is not None:
            vvm_payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

        self.client.publish(self.notify_version_topic, vvm_payload, qos=0)
        print("\n[Prime ECU] Success to Send Current VVM\n" + "="*50)
    
    def connect_mqtt(self):
        self.client.connect(self.MQTT_BROKER, self.MQTT_PORT, 60)

    def loop_mqtt(self):
        self.client.loop_start()

    def on_connect(self, client, userdata, flags, rc, properties=None):
        print(f"[Prime ECU] Connected: {rc}")

        client.subscribe(self.update_meta_topic)

    def on_message(self, client, userdata, msg):
        if msg.topic == self.update_meta_topic:
            payload = json.loads(msg.payload.decode("utf-8"))
            print("Got a metadata: " + payload["signed"]["_type"] + "\n")

            if payload["signed"]["_type"] == "root":
                self.key_info = read_root(payload)
                verify_multi_signature(payload, self.key_info)
        pass

    def configure_tls(self, client, ca_cert, client_cert, client_key):
        client.tls_set(
            ca_certs = ca_cert,
            certfile = client_cert,
            keyfile = client_key,
            tls_version = ssl.PROTOCOL_TLSv1_2
        )
        client.tls_insecure_set(True)


if __name__ == "__main__":
    handler = PrimeEcuHandler("192.168.35.202", 8883)
    # handler.connect_mqtt()
    # handler.loop_mqtt()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        handler.client.loop_stop()