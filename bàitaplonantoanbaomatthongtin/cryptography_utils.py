from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib

def generate_aes_key_iv():
    return get_random_bytes(32), get_random_bytes(16)

def aes_encrypt(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext.encode(), AES.block_size))

def aes_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

def sha256_hash(data: bytes):
    return hashlib.sha256(data).hexdigest()

def rsa_encrypt_key(public_key_pem, key_bytes):
    key = RSA.import_key(public_key_pem)
    cipher = PKCS1_v1_5.new(key)
    return cipher.encrypt(key_bytes)

def rsa_decrypt_key(private_key_pem, enc_key):
    key = RSA.import_key(private_key_pem)
    cipher = PKCS1_v1_5.new(key)
    return cipher.decrypt(enc_key, None)

def sign_sha256(private_key_pem, message):
    key = RSA.import_key(private_key_pem)
    h = SHA256.new(message.encode())
    return pkcs1_15.new(key).sign(h)

def verify_sha256_signature(public_key_pem, message, signature):
    key = RSA.import_key(public_key_pem)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except:
        return False
