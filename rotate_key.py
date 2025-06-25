def run():
    import os
    import datetime
    import traceback
    import base64
    import json
    from dotenv import load_dotenv
    from firebase import db as firestore_db
    import firebase_admin
    from firebase_admin import credentials, db

    from encryption import (
        generate_ecc_keys,
        hybrid_encrypt,
        hybrid_decrypt,
        generate_aes_key,
        aes_encrypt,
        aes_decrypt
    )
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    print("🚀 Starting key rotation script...", flush=True)
    load_dotenv()

    if not firebase_admin._apps:
        encoded = os.getenv("FIREBASE_CREDENTIAL")
        decoded_json = json.loads(base64.b64decode(encoded).decode("utf-8"))
        cred = credentials.Certificate(decoded_json)
        firebase_admin.initialize_app(cred, {
            "databaseURL": "https://crisis-survivor-default-rtdb.firebaseio.com"
        })

    database_ref = db.reference(path='/', url="https://crisis-survivor-default-rtdb.firebaseio.com")
    now = datetime.datetime.now()

    config_ref = firestore_db.collection("config").document("encryption_metadata")
    master_private_key_pem = os.getenv("MASTER_ECC_PRIVATE_KEY").replace("\\n", "\n").encode()
    master_private_key = serialization.load_pem_private_key(
        master_private_key_pem,
        password=None,
        backend=default_backend()
    )

    try:
        config_doc = config_ref.get()
        config_data = config_doc.to_dict() or {}
        encrypted_ecc_key = config_data.get("encrypted_ecc_key")
        encrypted_aes_key = config_data.get("encrypted_aes_key")
        print("📄 Loaded config from Firestore.", flush=True)
    except Exception:
        print("🔥 Firestore unavailable. Skipping key rotation.", flush=True)
        print(traceback.format_exc(), flush=True)
        return

    is_first_time = encrypted_ecc_key is None

    def rotate_chat_branch(branch_name, old_key, new_key):
        print(f"🔁 Rotating messages under: chat/{branch_name}/", flush=True)
        branch_ref = database_ref.child(f"chat/{branch_name}")
        chat_threads = branch_ref.get()
        if not chat_threads:
            print(f"⚠️ No chat threads in {branch_name}", flush=True)
            return

        for chat_id, chat_data in chat_threads.items():
            messages = chat_data.get("messages", {})
            updated_messages = {}
            for msg_id, msg in messages.items():
                try:
                    decrypted = aes_decrypt(old_key, msg["text"])
                    re_encrypted = aes_encrypt(new_key, decrypted)
                    updated_messages[msg_id] = {
                        "from": msg["from"],
                        "to": msg["to"],
                        "text": re_encrypted,
                        "timestamp": msg.get("timestamp")
                    }
                except Exception as e:
                    print(f"❌ Failed to rotate message {msg_id} in {chat_id}: {e}", flush=True)
            database_ref.child(f"chat/{branch_name}/{chat_id}/messages").set(updated_messages)

    if is_first_time:
        print("🆕 First-time setup — skipping message re-encryption.", flush=True)
        # Not rotating messages on first time
        return

    print("🔁 Rotating encryption keys...", flush=True)

    master_private_key_pem_str = master_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    decrypted_ecc_key_pem = hybrid_decrypt(master_private_key_pem_str, encrypted_ecc_key)["ecc_key"].encode()
    ecc_private_key = serialization.load_pem_private_key(
        decrypted_ecc_key_pem,
        password=None,
        backend=default_backend()
    )

    ecc_private_key_pem_str = ecc_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    decrypted_aes_hex = hybrid_decrypt(ecc_private_key_pem_str, encrypted_aes_key)["aes_key"]
    old_aes_key = bytes.fromhex(decrypted_aes_hex)

    new_aes_key = generate_aes_key()
    new_ecc_private_key, new_ecc_public_key = generate_ecc_keys()

    new_ecc_public_pem = new_ecc_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    new_encrypted_aes_key = hybrid_encrypt(new_ecc_public_pem, {"aes_key": new_aes_key.hex()})

    new_master_public_pem = master_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    new_encrypted_ecc_key = hybrid_encrypt(new_master_public_pem, {
        "ecc_key": new_ecc_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
    })

    # 🔁 Rotate medical and safety chat messages
    rotate_chat_branch("medical", old_aes_key, new_aes_key)
    rotate_chat_branch("safety", old_aes_key, new_aes_key)

    # 🔁 You can also rotate other collections like "users" here if needed

    config_ref.set({
        "encrypted_ecc_key": new_encrypted_ecc_key,
        "encrypted_aes_key": new_encrypted_aes_key,
        "last_rotation": now
    })
    print("✅ Keys rotated and chat messages updated.", flush=True)

run()
