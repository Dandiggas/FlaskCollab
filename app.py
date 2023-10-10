from flask import Flask, request, jsonify
import os
import hashlib
import argparse
import base64
import json
import hmac
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)

users_db = {}

CERT_PEM_PATH = 'certificate/cert.pem'
KEY_PEM_PATH = 'certificate/key.pem'
JWT_SIG_KEY = os.urandom(24).hex() # A random key for signing JWT tokens
SALT_LENGTH = 16

# scrypt parameters
N = 16384 # CPU/memory cost factor. Must be a power of 2.
R = 8     # Block size
P = 1     # Parallelization factor

def verify_jwt(token: str) -> dict:
    try:
        header_encoded, payload_encoded, signature_encoded = token.split(".")
        payload = json.loads(base64.urlsafe_b64decode(payload_encoded + "==").decode("utf-8"))
        expected_signature = encode_jwt_signature(header_encoded, payload_encoded)
        if signature_encoded != expected_signature:
            raise ValueError("Signature mismatch.")
        return payload
    except Exception as e:
        print(f"JWT verification error: {e}")
        return None

def requires_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"message": "Missing or invalid token"}), 403
        token = auth_header.split(" ")[1]
        payload = verify_jwt(token)
        if not payload:
            return jsonify({"message": "Invalid token"}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/my-user-page', methods=['GET'])
@requires_auth
def hello():
    return "hello world"

@app.route('/register', methods=['POST'])
def register():
    global use_salting

    data = request.get_json()
    if 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Username and password are required.'}), 400
    
    username = data['username']
    password = data['password'].encode("utf-8") # scrypt expects bytes so we use encode()
    salt = os.urandom(SALT_LENGTH) if use_salting else b''
    hashed_password = hashlib.scrypt(password, salt=salt, n=N, r=R, p=P) 
    
    if username in users_db:
        return jsonify({'message': 'Username already exists.'}), 400
    
    users_db[username] = {'salt': salt, 'hashed_password': hashed_password}
    print(users_db)
    
    return jsonify({'message': 'Registration successful.'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Username and password are required.'}), 400
    
    username = data['username']
    password = data['password'].encode("utf-8")
    
    if username not in users_db:
        return jsonify({'message': 'Username not found.'}), 401
    
    stored_salt = users_db[username]['salt']
    hashed_password = hashlib.scrypt(password, salt=stored_salt, n=N, r=R, p=P) 
    stored_password = users_db[username]['hashed_password']

    if stored_password == hashed_password:

        payload = {
            "username": username,
            "exp": (datetime.utcnow() + timedelta(days=1)).timestamp()  # 1 day expiration
        }

        token = generate_jwt(payload)
        return jsonify({'message': 'Login successful.', 'token': token}), 200
    else:
        return jsonify({'message': 'Incorrect password.'}), 401

def generate_jwt(payload: dict) -> str:
    header_encoded = encode_jwt_header()
    payload_encoded = encode_jwt_payload(payload)
    signature_encoded = encode_jwt_signature(header_encoded, payload_encoded)
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"

def encode_jwt_header():
    header = {
        "alg": "HS256",
        "typ": "JWT"
    }
    header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    return header_encoded

def encode_jwt_payload(payload: dict):
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return encoded_payload

def encode_jwt_signature(b64_encoded_header: str, b64_encoded_payload: str):
    signature = hmac.new(JWT_SIG_KEY.encode("utf-8"), (b64_encoded_header + '.' + b64_encoded_payload).encode("utf-8"), hashlib.sha256).digest()
    b64_encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return b64_encoded_signature

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="My Python App")

    # Add the --enable-salting flag. The 'action' parameter is set to 'store_true', which means the corresponding variable will be set to True if the flag is provided.
    parser.add_argument("--enable-salting", help="Enable salting feature", action="store_true")

    # Parse the command line arguments
    args = parser.parse_args()

    global use_salting
    use_salting = args.enable_salting

    if os.path.exists(CERT_PEM_PATH) and os.path.exists(KEY_PEM_PATH):
        app.run(debug=True, port=2000, ssl_context=(CERT_PEM_PATH, KEY_PEM_PATH))
    else:
        print("Certificate and key not found, starting in HTTP mode.")
        app.run(debug=True, port=2000)