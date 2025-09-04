import json
import base64
from datetime import datetime, timezone
from ecdsa import VerifyingKey, BadSignatureError
import os

# Threshold 검증용 공개키 폴더
KEY_DIR = "./keys_out"
TIME_THRESHOLD = 300  # 초 단위

def verify_multi_signature(payload_json_path):
    try:
        # JSON 읽기
        with open(payload_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        signed = data.get("signed")
        signatures = data.get("signatures", [])

        if not signed or not signatures:
            print("[Error] Invalid payload format")
            return False

        # timestamp 확인
        timestamp_str = signed.get("timestamp")
        if timestamp_str:
            timestamp = datetime.fromisoformat(timestamp_str)
            now = datetime.now(timezone.utc)
            if abs((now - timestamp).total_seconds()) > TIME_THRESHOLD:
                print(f"[Error] Timestamp out of range. Diff: {(now - timestamp).total_seconds()}s")
                return False

        # threshold 확인
        role_type = signed.get("_type", "unknown")
        threshold = signed.get("threshold", 1)  # 기본 1
        if "_type" in signed and "threshold" in signed:
            threshold = signed["threshold"]

        verify_bytes = json.dumps(signed, sort_keys=True, separators=(',', ':')).encode()

        verify_count = 0
        for sig_info in signatures:
            keyid = sig_info["keyid"]
            sig_b64 = sig_info["sig"]
            pem_path = os.path.join(KEY_DIR, f"{keyid}.pem")

            if not os.path.exists(pem_path):
                print(f"[Warning] Public key not found: {pem_path}")
                continue

            with open(pem_path, "rb") as f:
                vk = VerifyingKey.from_pem(f.read())

            sig_bytes = base64.b64decode(sig_b64)
            try:
                vk.verify(sig_bytes, verify_bytes)
                print(f"[OK] Verified: {keyid}")
                verify_count += 1
            except BadSignatureError:
                print(f"[Fail] Bad signature: {keyid}")

            if verify_count >= threshold:
                break

        if verify_count >= threshold:
            print("[Success] Multi-signature verification passed")
            return True
        else:
            print("[Fail] Multi-signature verification failed")
            return False

    except Exception as e:
        print(f"[Error] Exception during verification: {e}")
        return False