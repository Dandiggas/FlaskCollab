import unittest
import json
import base64
import hmac
import hashlib
from app import encode_jwt_header, encode_jwt_payload, encode_jwt_signature, JWT_SIG_KEY

class AddTest(unittest.TestCase):

    def test_helper_encode_header(self):
        header = {
            "alg": "HS256",
            "typ": "JWT"
        }
        b64_header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        assert b64_header_encoded == encode_jwt_header()

    def test_helper_encode_payload(self):
        payload = {
          "sub": "1234567890",
          "name": "John Doe",
          "iat": 1615488269,
          "exp": 1615574669,
          "isAdmin": True,
          "roles": ["user", "admin"],
          "email": "johndoe@example.com"
        }
        b64_encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        assert b64_encoded_payload == encode_jwt_payload(payload)

    def test_helper_encode_signature(self):
        payload = {
          "sub": "1234567890",
          "name": "John Doe",
          "iat": 1615488269,
          "exp": 1615574669,
          "isAdmin": True,
          "roles": ["user", "admin"],
          "email": "johndoe@example.com"
        }
        b64_encoded_header = encode_jwt_header()
        b64_encoded_payload = encode_jwt_payload(payload)
        signature = hmac.new(JWT_SIG_KEY.encode("utf-8"), (b64_encoded_header + '.' + b64_encoded_payload).encode("utf-8"), hashlib.sha256).digest()
        b64_encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        assert b64_encoded_signature == encode_jwt_signature(b64_encoded_header, b64_encoded_payload)

