import os
import json
import hashlib
import random
from datetime import datetime, timedelta
from manage_key import makeKeys, makeECUKeys, makeSignature, verifySignature

# Read keys
def loadKeys(keyType, directory='.'):
    pem_files = [
        f for f in os.listdir(directory)
        if f.lower().endswith(".pem") and f.lower().startswith(keyType)
    ]
    keys_data = {}

    for pem_file in pem_files:
        with open(pem_file, "rb") as f:
            pem_content = f.read()

        keyId = hashlib.sha256(pem_content).hexdigest()

        keys_data[keyId] = {
            "keytype": "ecdsa-NIST384p",
            "scheme": "ecdsa-NIST384p",
            "keyval": {
                "public": pem_content.decode("utf-8").strip()
            },
            "filename": pem_file
        }
    return keys_data

# Make Root metadata
def generate_root(root_threshold, targets_threshold):
    # Expires date
    expires_date = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Define Roles
    keys = loadKeys("verify")
    keyIds = list(keys.keys())

    if root_threshold > len(keyIds) or targets_threshold > len(keyIds):
        raise ValueError("Threshold cannot be greater than number of keys available")
    
    root_keys = random.sample(keyIds, root_threshold)
    targets_keys = random.sample(keyIds, targets_threshold)

    role_data = {
        "root": {
            "keyids": root_keys,
            "threshold": root_threshold
        },
        "targets": {
            "keyids": targets_keys,
            "threshold": targets_threshold
        }
    }
    
    # Make Raw data
    signed_content = {
        "_type": "root",
        "spec_version": "1.0.0",
        "version": 1,
        "expires": expires_date,
        "keys": {k: {kk: vv for kk, vv in v.items() if kk != "filename"} for k, v in keys.items()},
        "roles": role_data
    }

    # Make Signatures
    signatures = []
    signed_bytes = json.dumps(signed_content, separators=(',', ':'), sort_keys=True).encode("utf-8")

    for keyid in role_data["root"]["keyids"]:
        verify_filename = keys[keyid]["filename"]
        sign_filename = verify_filename.replace("verifyKey", "signKey")

        if not os.path.exists(sign_filename):
            raise FileNotFoundError(f"Signing key {sign_filename} not found for {verify_filename}")
        
        sig_b64 = makeSignature(sign_filename, signed_bytes)
        signatures.append({
            "keyid": keyid,
            "sig": sig_b64.decode("utf-8")
        })

    root_structure = {
        "signatures": signatures,
        "signed": signed_content
    }

    with open("root.json", "w", encoding="utf-8") as f:
        json.dump(root_structure, f, indent=2)

    print("\n", '='*50, "\nGenerate Root metadata\n", '='*50)

# Make ECU Version Report
def generate_version_report():
    rawData = {
        "ecu_serial": "brake_ecu_002",
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "installed_image": {
            "filepath": "brake_ecu_v1.5.bin",
            "fileinfo": {
                "length": 52488,
                "hashes": "b5d4045c3f466fa..."
            }
        }
    }

    signatures = []
    signed_bytes = json.dumps(rawData, separators=(',', ':'), sort_keys=True).encode("utf-8")

    makeECUKeys(rawData["ecu_serial"])
    signed_content = makeSignature(f"signKey_{rawData['ecu_serial']}.pem", signed_bytes)

    with open(f"signKey_{rawData['ecu_serial']}.pem", "rb") as f:
        pem_content = f.read()

    keyId = hashlib.sha256(pem_content).hexdigest()
    signatures.append({
        "keyid": keyId,
        "sig": signed_content.decode("utf-8")
    })

    os.makedirs("version_report", exist_ok=True)

    report_structure = {
        "signature": signatures,
        "signed": rawData
    }

    with open(f"version_report/{rawData['ecu_serial']}.json", "w", encoding="utf-8") as f:
        json.dump(report_structure, f, indent=2)

    print("\n", '='*50, "\nGenerate Version Report\n", '='*50)

# Make Vehicle Version Manifest
def generate_vvm():
    # Basic Info
    vin = "1HGBH41JXMN109186"
    expires_date = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Collect Reports
    reports = []
    for report in os.listdir("./version_report"):
        if report.lower().endswith(".json"):
            with open(os.path.join("version_report", report), "r", encoding="utf-8") as f:
                reportData = json.load(f)
            reports.append(reportData)

    rawData = {
        "vin": vin,
        "primary_ecu_serial": "primary0",
        "ecu_version_report": reports
    }

    # Make Signatures
    signatures = []
    signed_bytes = json.dumps(rawData, separators=(',', ':'), sort_keys=True).encode("utf-8")

    makeECUKeys(rawData["primary_ecu_serial"])
    signed_content = makeSignature(f"signKey_{rawData['primary_ecu_serial']}.pem", signed_bytes)

    with open(f"signKey_{rawData['primary_ecu_serial']}.pem", "rb") as f:
        pem_content = f.read()

    keyId = hashlib.sha256(pem_content).hexdigest()
    signatures.append({
        "keyid": keyId,
        "sig": signed_content.decode("utf-8")
    })

    vvm_structure = {
        "signature": signatures,
        "signed": rawData
    }

    with open("vehicle_version_manifest.json", "w", encoding="utf-8") as f:
        json.dump(vvm_structure, f, indent=2)

    print("\n", '='*50, "\nGenerate Vehicle Version Manifest\n", '='*50)

# Get key informations
def read_root(metadata, output_dir="keys_out"):
    with open(metadata, "r", encoding="utf-8") as f:
        rawData = json.load(f)

    keys_dict = rawData["signed"]["keys"]
    os.makedirs(output_dir, exist_ok=True)
    key_map = {}

    for keyid, keyinfo in keys_dict.items():
        public_pem = keyinfo["keyval"]["public"]
        pem_path = os.path.join(output_dir, f"{keyid}.pem")

        with open(pem_path, "w", encoding="utf-8") as pem_file:
            pem_file.write(public_pem)

        key_map[keyid] = pem_path

    key_for_meta = {}
    roles = rawData["signed"]["roles"]

    for role_name, role_info in roles.items():
        key_for_meta[role_name] = {
            "threshold": role_info["threshold"],
            "keyids": role_info["keyids"]
        }

    return key_for_meta

# Verify metadata(multi-signature verification)
def verify_multi_signature(metadata, key_info, output_dir="keys_out"):
    with open(metadata, "r", encoding="utf-8") as f:
        rawData = json.load(f)

    verify_content = json.dumps(rawData["signed"], separators=(',', ':'), sort_keys=True).encode("utf-8")  
    threshold = key_info[rawData["signed"]["_type"]]["threshold"]
    verifyCnt = 0
    
    for sig_info in rawData["signatures"]:
        vk_hash = sig_info["keyid"]
        signature = sig_info["sig"]

        pem_path = os.path.join(output_dir, f"{vk_hash}.pem")

        if not os.path.exists(pem_path):
            print(f"Key file not found: {pem_path}")
            continue

        if not verifySignature(pem_path, signature, verify_content):
            print(f"Fail to verify : {vk_hash}")
        else:
            print(f"Success Verification: {vk_hash}")
            verifyCnt += 1

            if verifyCnt == threshold:
                break

    if verifyCnt >= threshold:
        print("Success the Multi-Signature Verification")
    else:
        print("Fail the Multi-Signature Verification")

if __name__ == '__main__':
    generate_root(2, 2)
    key_info = read_root("./root.json")
    print(key_info)
    verify_multi_signature("./root.json", key_info)

    generate_version_report()
    generate_vvm()
