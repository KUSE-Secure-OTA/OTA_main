import os
import subprocess
from pathlib import Path

def generate_self_signed_cert(ip="10.222.88.12", cert_dir="./utils/certs", days=365):
    os.makedirs(cert_dir, exist_ok=True)
    cert_path = Path(cert_dir) / "https_server.crt"
    key_path = Path(cert_dir) / "https_server.key"

    subj = f"/C=KR/ST=Seoul/L=Seoul/O=MyOrg/OU=Dev/CN={ip}"
    san = f"subjectAltName=IP:{ip},DNS:localhost"

    print("🔧 Generating self-signed certificate...")
    try:
        subprocess.run([
            "openssl", "req", "-x509", "-nodes", "-days", str(days),
            "-newkey", "rsa:2048",
            "-keyout", str(key_path),
            "-out", str(cert_path),
            "-subj", subj,
            "-addext", san
        ], check=True)
        print(f"✅ Certificate created at: {cert_path}")
        print(f"✅ Private key created at: {key_path}")
    except subprocess.CalledProcessError as e:
        print("❌ Error generating certificate:", e)
        exit(1)

if __name__ == "__main__":
    generate_self_signed_cert()

