import paho.mqtt.client as mqtt
import base64
import time
import json

from ecdsa import SigningKey, VerifyingKey, NIST384p
from datetime import datetime, timezone

def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print("connected OK")
    else:
        print("Error: Connection fail, Return code =" ,reason_code)

def on_disconnect(client,userdata,flags,rc = 0):
    print(str(rc),end='\n')

def on_publish(client,userdata,mid):
    print("In on_pub call back mid = ", mid,end='\n')

def get_current_utc_time():
    return datetime.now(timezone.utc).isoformat()

def make_payload_with_signature(data):
    data["timestamp"] = get_current_utc_time()
    message = json.dumps(data, sort_keys=True).encode()

    sk = SigningKey.from_pem(open("./utils/signature/private_master.pem").read())
    signature = sk.sign(message)

    data["signature"] = base64.b64encode(signature).decode()

    #print("Payload:     ", data, "\n\n", "=" * 50)

    return json.dumps(data)

if __name__ == "__main__":
    # MQTT Setting
    client = mqtt.Client(protocol=mqtt.MQTTv5)

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish

    json_message = make_signature_file("./update.json")

    # Publish MQTT
    while True:
        client.connect("192.168.86.30", 1883)
        # client.connect("192.168.0.106", 1883)
        client.loop_start()
        try:
            print("Publish:    ", json_message)
            client.publish("OTA", json_message, 2, retain= False)
            print("Success Publish")
            time.sleep(2)

        except KeyboardInterrupt:
            print("Terminating...")

        
        client.loop_stop()
        client.disconnect()
