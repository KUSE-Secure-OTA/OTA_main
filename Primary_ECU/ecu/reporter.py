import json, time
import paho.mqtt.client as mqtt

class Reporter:
    """업데이트 결과/상태를 MQTT로 보고하는 역할."""

    def __init__(self, client: mqtt.Client, topic: str):
        self.client = client
        self.topic = topic

    def report(self, status: str, payload: dict | None = None, qos: int = 1, retain: bool = False):
        msg = {"status": status, "ts": int(time.time())}
        if payload:
            msg.update(payload)
        self.client.publish(self.topic, json.dumps(msg, ensure_ascii=False), qos=qos, retain=retain)

    def ok(self, version: str):
        self.report("success", {"version": version})

    def rollback(self, version: str):
        self.report("rollback", {"version": version})

    def error(self, reason: str, extra: dict | None = None):
        p = {"reason": str(reason)}
        if extra:
            p.update(extra)
        self.report("error", p)
