# sender.py
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Cipher import PKCS1_v1_5, DES
from Crypto.Random import get_random_bytes
import hashlib
from base64 import b64encode
import json
import os

def handshake():
    print("Sender: Hello!")
    print("Receiver: Ready!")

def generate_rsa_keys():
    key = RSA.generate(1024)
    with open("sender_private.pem", "wb") as f:
        f.write(key.export_key())
    with open("receiver_public.pem", "wb") as f:
        f.write(key.publickey().export_key())

def sign_and_encrypt_session_key(filename, parts_count):
    timestamp = "2025-06-27T12:00:00"
    metadata = f"{filename}|{timestamp}|{parts_count}"

    private_key = RSA.import_key(open("sender_private.pem").read())
    public_key = RSA.import_key(open("receiver_public.pem").read())

    hash_obj = SHA512.new(metadata.encode())
    signature = pkcs1_15.new(private_key).sign(hash_obj)

    session_key = get_random_bytes(8)
    cipher_rsa = PKCS1_v1_5.new(public_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    with open("metadata.bin", "wb") as f:
        f.write(metadata.encode())
    with open("signature.bin", "wb") as f:
        f.write(signature)
    with open("encrypted_session_key.bin", "wb") as f:
        f.write(encrypted_session_key)

    return session_key

def encrypt_and_hash_parts(filename, session_key):
    with open(filename, "rb") as f:
        content = f.read()

    part_size = len(content) // 3
    parts = [content[i * part_size:(i + 1) * part_size] for i in range(3)]
    if len(content) % 3 != 0:
        parts[-1] += content[3 * part_size:]

    private_key = RSA.import_key(open("sender_private.pem").read())
    for idx, part in enumerate(parts):
        iv = get_random_bytes(8)
        cipher = DES.new(session_key, DES.MODE_CBC, iv)

        pad_len = 8 - len(part) % 8
        part += bytes([pad_len]) * pad_len

        cipher_text = cipher.encrypt(part)
        hash_val = hashlib.sha512(iv + cipher_text).hexdigest()

        hash_obj = SHA512.new(iv + cipher_text)
        sig = pkcs1_15.new(private_key).sign(hash_obj)

        packet = {
            "iv": b64encode(iv).decode(),
            "cipher": b64encode(cipher_text).decode(),
            "hash": hash_val,
            "sig": b64encode(sig).decode()
        }

        with open(f"packet_part_{idx+1}.json", "w") as f:
            json.dump(packet, f, indent=2)

    print("Sender: Đã tạo 3 phần và gửi đi.")

if __name__ == "__main__":
    handshake()
    if not os.path.exists("sender_private.pem") or not os.path.exists("receiver_public.pem"):
        generate_rsa_keys()

    session_key = sign_and_encrypt_session_key("assignment.txt", 3)
    encrypt_and_hash_parts("assignment.txt", session_key)
