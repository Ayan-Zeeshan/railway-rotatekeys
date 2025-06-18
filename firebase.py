import os, json, base64
import firebase_admin
from firebase_admin import auth, credentials
from dotenv import load_dotenv
from firebase_admin import firestore

load_dotenv()  # in case you're loading from .env
# import json
# firebase_key = json.loads(os.environ["FIREBASE_SERVICE_ACCOUNT_JSON"])
# firebase_key["private_key"] = firebase_key["private_key"].replace("\\n", "\n")
# cred = credentials.Certificate(firebase_key)

# if not firebase_admin._apps:
#     cred = credentials.Certificate({
#         "type": "service_account",
#         "project_id": os.getenv("FIREBASE_PROJECT_ID"),
#         "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
#         "private_key": os.getenv("FIREBASE_PRIVATE_KEY"),#.replace('\\n', '\n'),
#         "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
#         "client_id": os.getenv("FIREBASE_CLIENT_ID"),
#         "auth_uri": "https://accounts.google.com/o/oauth2/auth",
#         "token_uri": "https://oauth2.googleapis.com/token",
#         "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
#         "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_CERT_URL")
#     })
#     firebase_admin.initialize_app(cred)

# cred = credentials.Certificate("crisis-survivor-firebase-adminsdk-fbsvc-87aa3ee0c5.json")
# firebase_admin.initialize_app(cred)
# db = firestore.client()
    
# ✅ Export Firestore client
# db = firestore.client()

b64 = os.environ.get("FIREBASE_CREDENTIAL")

if not b64:
    raise Exception("FIREBASE_CREDENTIAL_BASE64 is not set.")

cred_dict = json.loads(base64.b64decode(b64))

# initialize_app(cred)

if not firebase_admin._apps:
        # cred = credentials.Certificate({
        #     "type": "service_account",
        #     "project_id": os.getenv("FIREBASE_PROJECT_ID"),
        #     "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
        #     "private_key": os.getenv("FIREBASE_PRIVATE_KEY"),#.replace('\\n', '\n'),
        #     "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
        #     "client_id": os.getenv("FIREBASE_CLIENT_ID"),
        #     "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        #     "token_uri": "https://oauth2.googleapis.com/token",
        #     "auth_provider_x509_cert_url": "https://www.googleapis.com/v1/certs",
        #     "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_CERT_URL")
        # })
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)

db = firestore.client()