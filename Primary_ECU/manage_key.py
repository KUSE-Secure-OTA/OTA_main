from ecdsa import SigningKey, VerifyingKey, NIST384p
import base64


def makeKeys(n):
    for i in range(n):
        sk = SigningKey.generate(curve=NIST384p)
        vk = sk.get_verifying_key()

        with open(f"signKey_{i}.pem", "wb") as f:
            f.write(sk.to_pem())

        with open(f"verifyKey_{i}.pem", "wb") as f:
            f.write(vk.to_pem())


def makeSignature(keyPath, data):
    try:
        with open(keyPath, "r") as f:
            sk = SigningKey.from_pem(f.read())
        signature = sk.sign(data)

        return base64.b64encode(signature)
    except Exception as e:
        raise RuntimeError(f"Fail to sign: {e}")

def verifySignature(keyPath, sig, message):
    vk = VerifyingKey.from_pem(open(keyPath).read())
    #vk = VerifyingKey.from_pem(keyPath)

    try:
        with open(keyPath, "r") as f:
            vk = VerifyingKey.from_pem(f.read())

        sig_bytes = base64.b64decode(sig)
        vk.verify(sig_bytes, message)
        return True
    except Exception as e:
        return False
    

if __name__ == "__main__":
    n = 3
    data = "Hello".encode("utf-8")
    makeKeys(n)

    for i in range(n):
        skPath = f"signKey_{i}.pem"
        vkPath = f"verifyKey_{i}.pem"

        signature = makeSignature(skPath, data)
        print(signature)

        print(verifySignature(vkPath, signature, data))

