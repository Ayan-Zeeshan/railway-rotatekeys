def run():
    import os
    import datetime
    import traceback
    from dotenv import load_dotenv
    from firebase import db
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
    now = datetime.datetime.utcnow()

    config_ref = db.collection("config").document("encryption_metadata")
    master_private_key_pem = os.getenv("MASTER_ECC_PRIVATE_KEY").encode()
    master_private_key = serialization.load_pem_private_key(
        master_private_key_pem,
        password=None,
        backend=default_backend()
    )

    try:
        config_doc = config_ref.get()
        config_data = config_doc.to_dict() or {}
        encrypted_ecc_key = config_data.get("encrypted_ecc_key")
        last_rotation = config_data.get("last_rotation")
        print("📄 Loaded config from Firestore.", flush=True)
    except Exception as e:
        print("🔥 Firestore unavailable. Skipping key rotation.", flush=True)
        print(traceback.format_exc(), flush=True)
        return

    is_first_time = encrypted_ecc_key is None

    if is_first_time:
        print("🆕 First-time setup. Generating keys and encrypting data...", flush=True)

        # ecc_private_key, ecc_public_key = generate_ecc_keys()
        ecc_private_pem, ecc_public_key = generate_ecc_keys()
        from cryptography.hazmat.primitives import serialization
        ecc_private_key = serialization.load_pem_private_key(
            ecc_private_pem.encode(),
            password=None,
            backend=default_backend()
        )   

        aes_key = generate_aes_key()

        encrypted_aes_key = hybrid_encrypt(ecc_public_key, {"aes_key": aes_key.hex()})
        master_public_pem = master_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

        encrypted_ecc_key = hybrid_encrypt(master_public_pem, {

            "ecc_key": ecc_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
        })

        docs = db.collection("users").stream()
        for doc in docs:
            doc_data = doc.to_dict()
            encrypted_fields = {}
            for k, v in doc_data.items():
                if v is None:
                    encrypted_fields[k] = None
                else:
                    encrypted_fields[k] = aes_encrypt(aes_key, v)
            doc.reference.set(encrypted_fields)
            print(f"✅ Encrypted doc: {doc.id}", flush=True)

        config_ref.set({
            "encrypted_ecc_key": encrypted_ecc_key,
            "encrypted_aes_key": encrypted_aes_key,
            "last_rotation": now
        })
        print("🔐 Stored encrypted keys in Firestore.", flush=True)

    else:
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

        encrypted_aes_key = config_data["encrypted_aes_key"]
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
        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

        new_encrypted_ecc_key = hybrid_encrypt(new_master_public_pem, {

            "ecc_key": new_ecc_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
        })

        docs = db.collection("users").stream()
        for doc in docs:
            doc_data = doc.to_dict()
            print(f"🧊 Encrypted doc from Firestore ({doc.id}): {doc_data}", flush=True)

            decrypted_fields = {}
            for k, encrypted_val in doc_data.items():
                if encrypted_val is None:
                    decrypted_fields[k] = None
                else:
                    decrypted_fields[k] = aes_decrypt(old_aes_key, encrypted_val)

            print(f"🔓 Decrypted fields: {decrypted_fields}", flush=True)

            re_encrypted_fields = {}
            for k, v in decrypted_fields.items():
                if v is None:
                    re_encrypted_fields[k] = None
                else:
                    re_encrypted_fields[k] = aes_encrypt(new_aes_key, v)
            
            print(f"🔐 Re-encrypted fields: {re_encrypted_fields}", flush=True)

            doc.reference.set(re_encrypted_fields)
            print(f"🔄 Rotated doc: {doc.id}", flush=True)

        config_ref.set({
            "encrypted_ecc_key": new_encrypted_ecc_key,
            "encrypted_aes_key": new_encrypted_aes_key,
            "last_rotation": now
        })
        print("✅ Updated encrypted keys in Firestore.", flush=True)
