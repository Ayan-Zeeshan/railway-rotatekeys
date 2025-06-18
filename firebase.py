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

b64 = "ewogICJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIsCiAgInByb2plY3RfaWQiOiAiY3Jpc2lzLXN1cnZpdm9yIiwKICAicHJpdmF0ZV9rZXlfaWQiOiAiODdhYTNlZTBjNTExNDU0NjBmN2RhYTE4ZjY0OWYyNjYyODc4M2U5MCIsCiAgInByaXZhdGVfa2V5IjogIi0tLS0tQkVHSU4gUFJJVkFURSBLRVktLS0tLVxuTUlJRXZnSUJBREFOQmdrcWhraUc5dzBCQVFFRkFBU0NCS2d3Z2dTa0FnRUFBb0lCQVFEem1MK0xYNHhHQ1cxNlxub2IyRUwrNzJCKzFoSVFUQ3BjZG52eWpuY3V1MHd3WFFOSmpwaU9WZ2lHYUYxbllNa0g4MEdyQnRDWTU0QUZWWFxuc1MySndLR0dVR3pYcDIxV1ozMjFsNjhNMjcvcUNNVXdwN1JGbnNSSEFpQi9COEZxZ3FPR3RPSXlGMnhVeFlTQVxubTQ0UzZYTFZ0cmliWGV1RGt0ZnE5UVFsSWhxU0xIMEkrVWxKQlcyOU1DU1l0bWpIZ3VXQWsvVmg4ZTFyTXl0SlxuTVVqdFpEb2FHZmdaMWdwajhTcUNtNmt6UFJjQUFEdmpMUWNyNC9ZeEpzYnl0Y1JneGp1SWx0Nk1CZ2hxNnVHd1xuVmxJcnJ3a2FPSFJ5M3paZzk3cmRJNWRVMGVsdm92cllFd0Q3SkRZdkxKT21pNWZiMm5DOGRaTkZVNHFNanU2MVxucVJWRSt6eTNBZ01CQUFFQ2dnRUFEU0kvdFphRnZDTDIvYVVwMEM0N2JwVjMxWVJQdXVUd1R1WXVJT2gveitPeFxuOVF0WThVSjV4NDRqSlBVdXNUZTdQQVp5VzdhbnNVMm5URTZYdTNVZzRGcUd1OHZocDhaMXJ5eEorbUlBdzNBTVxubmJaMUVFbmlvRWQ3bEEzSmZtSWp5ZmdIdUJhdU54WGRNb2Z3alpGN3FRMHNmK2Y4OGoraEY2QjFSRUZGK0hxRlxucG9HY25kdllVWFJjdlNyOHRnQXd3SThsb1NxMmg4WDZsSVR3SUFBZFJjOEx1TTcwTGZHb01oWTI2K0NlQTRiRlxuQlBWbW5mdmNQYjNqeXA1SWptbTlEN0dwc3Izem5RUzVtL0hicnN4cnhFK0xIa3FZclE2UDhROHZ0RHZKL1d2RlxucGlPSURVWnpabVpCYlFKYVJXWFNIdnRQWjV1WEZybXlZQkQ5Z0g5dFJRS0JnUUQrUk5QWUt1N1ZvTzVjRkVTclxuSWtHV3dxbnBJdTJ6WjVSSmxDQmMzV0d5WG1UT1BLZTdWR0I1K2pRcXJ3ZjlZNEZKeStCZStUMDNYQ0RSZ0xFSlxubERVMHZOTVNmT0VJSytDSFlwamNwNW9wRUxkMzJVME45TUpEQkM3N0xseDh4YzN6Tk92NDI5NFd3dzl2Skc0YVxuRzJNWmswOW9jLzdhbmtaZ3NCN2MrUjNCc3dLQmdRRDFRVkhoYzlXOU9CQ0E3MlpFTDFuUU9pTFZvZjVxbDZ1YlxuYm5aOFdabmt1a1dXMXFYUXBOdnJEZVlaVll3VlhOUWJURmFUdlQrcmV4RmQvVUxGRytDVDdxdFJKOWJFSFl0V1xuOVcwMlN1QU9CcFZab3d2V3pCMVh0UlZ5V2t2M215MnFwNnJnTjIrRHo5UkZhdGE1WEF0cyszbUhUaWxaSmxhc1xuMUczUWxmeHU3UUtCZ1FEaEFmRmg2dVE5WWROczRuYTk1bXVhU1J0bzl3TFlid0czZHdDSWpWUG1MMGdQaFhkOFxuKzdjQVdoeU41U1F4NUR0R0hjZW80L0I3SytqUzNJcE9DcnhtdGU0bS95RjRSTFBGdXNmQkJBUVU4UGthY3M2UVxuV2hjS2pRb3lOeDJiUU1QMnc4OUtBdTl1dnlES1hyZWNITDQrcExCeG82eFV0QmxkZUoxbk9JQlBwd0tCZ0h5UVxuYm92NWowZUpvQ2c4YjA2V1ZpR0NSWXNIdWZaZGpsVmxaMXlGRGJxME9RQUJpVHBOWVQwalZBanVBRFloYmNGblxucGxsbk4xMWJKbGo4ZHRzeDY0QjNLaUFRQWU2ZHF0WEIxWFJMMXp5SWIzYVZiei9yYjhQS1AxaFRNRjVVUEg5K1xucFRVNE1yVlo2MUJPa1R5WDJWM0M0OWlyQkNrNVpiQm1QRmhDdFhHSkFvR0JBT1Z2MGdWdzVxcVBiSU9UVzZNMVxuTHVvRG9uUExGa0FlV0RYZEdvZ04vSnBMUENZVjdlSDhPTm5HRUt0bEE2SGl5TytkMnJEc2g5K3lDOHRreS92VFxuUXQySmJvQ0laWFpvcklaVG56NUJta3NEam1nZERTVjZUcjRNbGlNOEs1OS9RT212TXh2T2hseVh4UDByQUp3eVxuY1JBNE92d2xmVW9jNktGRUtuOGtDbDY2XG4tLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tXG4iLAogICJjbGllbnRfZW1haWwiOiAiZmlyZWJhc2UtYWRtaW5zZGstZmJzdmNAY3Jpc2lzLXN1cnZpdm9yLmlhbS5nc2VydmljZWFjY291bnQuY29tIiwKICAiY2xpZW50X2lkIjogIjExMTA0OTA0NDM5MDg0OTA5NDAzNSIsCiAgImF1dGhfdXJpIjogImh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL29hdXRoMi9hdXRoIiwKICAidG9rZW5fdXJpIjogImh0dHBzOi8vb2F1dGgyLmdvb2dsZWFwaXMuY29tL3Rva2VuIiwKICAiYXV0aF9wcm92aWRlcl94NTA5X2NlcnRfdXJsIjogImh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL29hdXRoMi92MS9jZXJ0cyIsCiAgImNsaWVudF94NTA5X2NlcnRfdXJsIjogImh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL3JvYm90L3YxL21ldGFkYXRhL3g1MDkvZmlyZWJhc2UtYWRtaW5zZGstZmJzdmMlNDBjcmlzaXMtc3Vydml2b3IuaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20iLAogICJ1bml2ZXJzZV9kb21haW4iOiAiZ29vZ2xlYXBpcy5jb20iCn0="#os.getenv("FIREBASE_CREDENTIAL")

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