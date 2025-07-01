# receiver.py
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Cipher import PKCS1_v1_5, DES
import hashlib
from base64 import b64decode
import json

def verify_and_decrypt_packets():
    private_key = RSA.import_key(open("sender_private.pem").read())
    public_key = RSA.import_key(open("receiver_public.pem").read())

    metadata = open("metadata.bin", "rb").read()
    signature = open("signature.bin", "rb").read()

    hash_obj = SHA512.new(metadata)
    try:
        pkcs1_15.new(public_key).verify(hash_obj, signature)
    except (ValueError, TypeError):
        print("NACK: Metadata signature invalid.")
        return

    print("Receiver: Metadata hợp lệ.")

    encrypted_session_key = open("encrypted_session_key.bin", "rb").read()
    cipher_rsa = PKCS1_v1_5.new(private_key)
    session_key = cipher_rsa.decrypt(encrypted_session_key, None)

    final_data = b""
    for i in range(1, 4):
        with open(f"packet_part_{i}.json", "r") as f:
            packet = json.load(f)

        iv = b64decode(packet["iv"])
        cipher_data = b64decode(packet["cipher"])
        hash_val = packet["hash"]
        sig = b64decode(packet["sig"])

        computed_hash = hashlib.sha512(iv + cipher_data).hexdigest()
        if computed_hash != hash_val:
            print(f"NACK: Hash mismatch in part {i}")
            return

        hash_obj = SHA512.new(iv + cipher_data)
        try:
            pkcs1_15.new(public_key).verify(hash_obj, sig)
        except (ValueError, TypeError):
            print(f"NACK: Signature invalid in part {i}")
            return

        cipher = DES.new(session_key, DES.MODE_CBC, iv)
        plain = cipher.decrypt(cipher_data)
        pad_len = plain[-1]
        final_data += plain[:-pad_len]

    with open("assignment_received.txt", "wb") as f:
        f.write(final_data)

    print("ACK: File received, verified, and saved.")

if __name__ == "__main__":
    verify_and_decrypt_packets()
