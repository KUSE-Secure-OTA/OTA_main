import os
import json
import hashlib
import random
from datetime import datetime, timedelta
from manage_key import makeKeys, makeSignature, verifySignature

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

    # Define Rolse
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
        "_type": "Root",
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

# Renew signatures

# Make Target metadata


# Verify metadata(multi-signature verification)
def verify_multi_signature(metadata, keyTable, n, output_dir="keys_out"):
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
    #key_map = {keyid: keyinfo["keyval"]["public"] for keyid, keyinfo in keys_dict.items()}

    verify_content = json.dumps(rawData["signed"], separators=(',', ':'), sort_keys=True).encode("utf-8")  
    verifyCnt = 0
    
    for i in range(len(rawData["signatures"])):
        vk_hash = rawData["signatures"][i]["keyid"]
        signature = rawData["signatures"][i]["sig"]

        if not verifySignature(key_map[vk_hash], signature, verify_content):
            print(f"Fail to verify: {vk_hash}")
        else:
            print(f"Success Verification: {vk_hash}")
            verifyCnt += 1
            
            if verifyCnt == n:
                break

    if verifyCnt >= n:
        print("Success the Multi-Signature Verification")
    else:
        print("Fail the Multi-Signature Verification")



if __name__ == '__main__':
    generate_root(2,2)
    verify_multi_signature("./root.json", {}, 1)