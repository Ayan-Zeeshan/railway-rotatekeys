# import os 
# import base64
# import json
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.hazmat.primitives import hashes, serialization
# from dotenv import load_dotenv

# load_dotenv()

# # Load master ECC private key from .env
# MASTER_ECC_PRIVATE_KEY_PEM = os.getenv("MASTER_ECC_PRIVATE_KEY").encode()
# MASTER_ECC_PRIVATE_KEY = serialization.load_pem_private_key(
#     MASTER_ECC_PRIVATE_KEY_PEM,
#     password=None
# )

# def get_master_public_key():
#     return MASTER_ECC_PRIVATE_KEY.public_key()

# def generate_ecc_keys():
#     private_key = ec.generate_private_key(ec.SECP256R1())
#     public_key = private_key.public_key()

#     private_bytes = private_key.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.PKCS8,
#         encryption_algorithm=serialization.NoEncryption()
#     )
#     public_bytes = public_key.public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo
#     )

#     return private_bytes.decode(), public_bytes.decode()

# def hybrid_encrypt(public_key_pem, plaintext_dict):
#     public_key = serialization.load_pem_public_key(public_key_pem.encode())

#     # Generate ephemeral private key and shared secret
#     ephemeral_key = ec.generate_private_key(ec.SECP256R1())
#     shared_secret = ephemeral_key.exchange(ec.ECDH(), public_key)

#     # Derive AES key
#     aes_key = HKDF(
#         algorithm=hashes.SHA256(), length=32, salt=None, info=b'hybrid-enc'
#     ).derive(shared_secret)

#     aesgcm = AESGCM(aes_key)
#     nonce = os.urandom(12)
#     plaintext = json.dumps(plaintext_dict).encode()
#     ciphertext = aesgcm.encrypt(nonce, plaintext, None)

#     # Return all required fields
#     return {
#         'ciphertext': base64.b64encode(ciphertext).decode(),
#         'nonce': base64.b64encode(nonce).decode(),
#         'ephemeral_public_key': base64.b64encode(
#             ephemeral_key.public_key().public_bytes(
#                 encoding=serialization.Encoding.PEM,
#                 format=serialization.PublicFormat.SubjectPublicKeyInfo
#             )
#         ).decode()
#     }

# def hybrid_decrypt(private_key_pem, encrypted_payload):
#     private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
#     ephemeral_public_key = serialization.load_pem_public_key(
#         base64.b64decode(encrypted_payload['ephemeral_public_key'])
#     )

#     shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
#     aes_key = HKDF(
#         algorithm=hashes.SHA256(), length=32, salt=None, info=b'hybrid-enc'
#     ).derive(shared_secret)

#     aesgcm = AESGCM(aes_key)
#     nonce = base64.b64decode(encrypted_payload['nonce'])
#     ciphertext = base64.b64decode(encrypted_payload['ciphertext'])

#     plaintext = aesgcm.decrypt(nonce, ciphertext, None)
#     return json.loads(plaintext)
import os 
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from dotenv import load_dotenv

load_dotenv()

# Load master ECC private key from .env
# raw_key = os.getenv("MASTER_ECC_PRIVATE_KEY")

# if not raw_key:
#     raise ValueError("Missing MASTER_ECC_PRIVATE_KEY environment variable")

# # Convert escaped newlines to actual newlines
# pem_key = raw_key.replace("\\n", "\n").encode()

# # Load ECC private key
# MASTER_ECC_PRIVATE_KEY = serialization.load_pem_private_key(
#     pem_key,
#     password=None,
# )
# MASTER_ECC_PRIVATE_KEY_PEM = os.getenv("MASTER_ECC_PRIVATE_KEY").encode()
# MASTER_ECC_PRIVATE_KEY = serialization.load_pem_private_key(
#     MASTER_ECC_PRIVATE_KEY_PEM,
#     password=None
# )

def get_master_public_key():
    return MASTER_ECC_PRIVATE_KEY.public_key()

def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def generate_aes_key():
    return os.urandom(32)

def aes_encrypt(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, str(plaintext).encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()

def aes_decrypt(key, encrypted_data):
    data = base64.b64decode(encrypted_data)
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()

def hybrid_encrypt(public_key_pem, plaintext_dict):
    public_key = serialization.load_pem_public_key(public_key_pem.encode())

    # Generate ephemeral private key and shared secret
    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    shared_secret = ephemeral_key.exchange(ec.ECDH(), public_key)

    # Derive AES key
    aes_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b'hybrid-enc'
    ).derive(shared_secret)

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    plaintext = json.dumps(plaintext_dict).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Return all required fields
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'ephemeral_public_key': base64.b64encode(
            ephemeral_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode()
    }

def hybrid_decrypt(private_key_pem, encrypted_payload):
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    ephemeral_public_key = serialization.load_pem_public_key(
        base64.b64decode(encrypted_payload['ephemeral_public_key'])
    )

    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
    aes_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b'hybrid-enc'
    ).derive(shared_secret)

    aesgcm = AESGCM(aes_key)
    nonce = base64.b64decode(encrypted_payload['nonce'])
    ciphertext = base64.b64decode(encrypted_payload['ciphertext'])

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext)
