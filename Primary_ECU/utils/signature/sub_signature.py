import paho.mqtt.client as mqtt
import base64
import json
import time
from ecdsa import VerifyingKey, BadSignatureError
from datetime import datetime, timezone

MainTopic = "OTA"
brokerIp = "192.168.86.30"
port = 1883

json_file = "./receive_signature.json"

TIME_THRESHOLD = 100000

def verify_signature(payload):
    try:        
        with open(json_file, "wb") as f:
            f.write(payload)
        print(f"JSON file saved as {json_file}.")
        
        with open(json_file, "rb") as f:
            data = json.load(f)

        timestamp = data.get("timestamp")
        if timestamp is None:
            print("Missing 'timestamp' field in JSON data.")
            return False
        
        current_time = datetime.fromisoformat(datetime.now(timezone.utc).isoformat())
        timestamp = datetime.fromisoformat(timestamp)
    
        time_diff = current_time - timestamp
        if time_diff.total_seconds() > TIME_THRESHOLD:
            print(f"Message timestamp is out of allowed range. Time difference: {time_diff} seconds.")
            return False
        else:
            print(f"Message timestamp is valid. Time difference: {time_diff} seconds.")
        
        signature_b64 = data.get("signature")
        if signature_b64 is None:
            print("Missing 'message' or 'signature' field in JSON file.")
            return False

        message_data = {k: v for k, v in data.items() if k != "signature"}
        message = json.dumps(message_data, sort_keys=True).encode()
        #print("message = ", message)
        signature = base64.b64decode(signature_b64)
        
        with open("./utils/signature/public_backend.pem", "rb") as f:
            vk = VerifyingKey.from_pem(f.read())

        try:
            vk.verify(signature, message)
            print("\n##### Signature verified successfully. #####")
        except BadSignatureError:
            print("\n%%%%%% Signature verification failed: Bad signature. %%%%%")
        
        #print("Received message:", message)

        return True
        
    except Exception as e:
        print("Error processing message:", e)
        return False


def on_connect(client, userdata, flags, reasonCode):
    if reasonCode == 0:
        print("Connected successfully.")
        client.subscribe(MainTopic)
    else:
        print(f"Failed to connect, return code {reasonCode}")

def on_disconnect(client, userdata, flags, rc=0):
    print(str(rc)+'/')

def on_message(client, userdata, msg):
    print(verify_signature(msg.payload))

if __name__ == '__main__':
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(brokerIp, port, keepalive=60)
    client.loop_forever()
