from flask import Flask, request, jsonify
from collections import namedtuple
import os
import hashlib
import argparse
import base64
import json
import hmac
from functools import wraps
from datetime import datetime, timedelta
import sqlite3

app = Flask(__name__)

CERT_PEM_PATH = 'certificate/cert.pem'
KEY_PEM_PATH = 'certificate/key.pem'
JWT_SIG_KEY = os.urandom(24).hex() # A random key for signing JWT tokens
SALT_LENGTH = 16
DB_NAME = "USER_DB"
DB_TABLE_USER = "USERS"

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
        if datetime.utcnow().timestamp() > payload.get("exp"):
            raise ValueError("Token has expired.")
        return payload
    except Exception as e:
        print(f"JWT verification error: {e}")
        return None

# Appends headers to be consumed by the browser, indicating what the allowed origins, methods and headers are for incoming requests
def add_cors_headers(response, methods=None, headers=None, allow_credentials=False):
    if enable_cors:
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000' # TODO: Parametrize / fetch from file the allowed origins
        response.headers['Access-Control-Allow-Methods'] = ', '.join(methods) if methods != None else ''
        response.headers['Access-Control-Allow-Headers'] = ', '.join(headers) if headers != None else ''
        response.headers['Access-Control-Allow-Credentials'] = str(allow_credentials).lower()
    return response

def requires_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.path.startswith('/userpage') and request.method == 'OPTIONS':
            return add_cors_headers(jsonify({}), methods=['GET'], headers=['Origin', 'Accept', 'Content-Type', 'Authorization'])
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"message": "Missing or invalid token"}), 403
        token = auth_header.split(" ")[1]
        payload = verify_jwt(token)
        if not payload:
            return jsonify({"message": "Invalid token"}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/userpage/<username>', methods=['GET', 'OPTIONS'])
@requires_auth
def userpage(username):
    auth_header = request.headers.get("Authorization")
    token = auth_header.split(" ")[1] # Splitting "Bearer <jwt-token>"
    payload = verify_jwt(token)

    # Check if the username in the JWT matches the username in the URL
    if payload and payload.get("username") == username:
        response = f"Hello, {username}!"
        return add_cors_headers(jsonify(response), methods=['GET'], headers=['Origin', 'Accept', 'Content-Type', 'Authorization']), 200
    else:
        response = "You are not authorized to view this page."
        return add_cors_headers(jsonify(response), methods=['GET'], headers=['Origin', 'Accept', 'Content-Type', 'Authorization']), 403
    
@app.route('/register', methods=['POST', 'OPTIONS'])
def register():
    global use_salting
    if request.method == 'OPTIONS':
        return add_cors_headers(jsonify({}), methods=['POST'], headers=['Origin', 'Accept', 'Content-Type', 'Authorization'])

    data = request.get_json()
    if 'username' not in data or 'password' not in data:
        response = jsonify({'message': 'Username and password are required.'})
        return add_cors_headers(response, methods=['POST'], headers=['Origin', 'Accept', 'Content-Type', 'Authorization']), 400
    
    username = data['username']
    password = data['password'].encode("utf-8") # scrypt expects bytes so we use encode()
    salt = os.urandom(SALT_LENGTH) if use_salting else b''
    hashed_password = hashlib.scrypt(password, salt=salt, n=N, r=R, p=P) 
    
    try: 
        user = select_user(username)
        if user:
            response = jsonify({'message': 'Username already exists.'})
            return add_cors_headers(response, methods=['POST'], headers=['Origin', 'Accept', 'Content-Type', 'Authorization']), 400
    except:
        pass
    
    new_user = {'name': username, 'salt': salt, 'hashed_password': hashed_password, 'role': 'user'}
    insert_user(new_user)
    
    response = jsonify({'message': 'Registration successful.'})
    return add_cors_headers(response, methods=['POST'], headers=['Origin', 'Accept', 'Content-Type', 'Authorization']), 201

@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return add_cors_headers(jsonify({}), methods=['POST'], headers=['Origin', 'Accept', 'Content-Type', 'Authorization'])
    data = request.get_json()
    if 'username' not in data or 'password' not in data:
        response = {'message': 'Username and password are required.'}
        return add_cors_headers(jsonify(response), methods=['POST'], headers=['Origin', 'Accept', 'Content-Type', 'Authorization']), 400
    
    username = data['username']
    password = data['password'].encode("utf-8")
    
    try:
        user_in_db = select_user(username)
    except:
        response = {'message': 'Username not found.'}
        return add_cors_headers(jsonify(response), methods=['POST'], headers=['Origin', 'Accept', 'Content-Type', 'Authorization']), 401
    
    stored_salt = user_in_db.salt
    hashed_password = hashlib.scrypt(password, salt=stored_salt, n=N, r=R, p=P) 
    stored_password = user_in_db.hashed_password

    if stored_password == hashed_password:
        payload = {
            "username": username,
            "exp": (datetime.utcnow() + timedelta(days=1)).timestamp()  # 1 day expiration
        }
        token = generate_jwt(payload)
        response = {'message': 'Login successful.', 'token': token}
        return add_cors_headers(jsonify(response), methods=['POST'], headers=['Origin', 'Accept', 'Content-Type', 'Authorization']), 200
    else:
        response = {'message': 'Incorrect password.'}
        return add_cors_headers(jsonify(response), methods=['POST'], headers=['Origin', 'Accept', 'Content-Type', 'Authorization']), 401

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

def insert_user(user):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO USERS (name, salt, hashed_password, role) VALUES (?, ?, ?, ?)", (user['name'], user['salt'], user['hashed_password'], user['role']))
    conn.commit()
    conn.close()

def select_user(user_name: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM USERS WHERE name = ?", (user_name,))
    row = cursor.fetchone()

    if row is None:
        raise Exception('User not found')
    
    # Define a namedtuple type
    User = namedtuple('User', 'id name hashed_password salt role')

    # Convert the row to a named tuple
    user = User(*row)
    
    conn.close()
    return user

def initialize_database(db_path, table_name):
    # Check if the database file exists
    db_exists = os.path.exists(db_path)

    # Connect to the database; this will create it if it doesn't exist
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    if not db_exists:
        # If the database didn't exist, it's safe to assume the table doesn't exist
        print("Database not found. Created new database.")
        create_table(cursor, table_name)
    else:
        # If the database did exist, we need to check for the table
        print("Database found. Checking if table exists...")
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{DB_TABLE_USER}';")

        # If the table doesn't exist, create it
        if not cursor.fetchone():
            print(f"Table '{DB_TABLE_USER}' not found in the database. Creating new table.")
            create_table(cursor, table_name)
        else:
            print(f"Table '{DB_TABLE_USER}' exists.")

    # Don't forget to commit and close the connection
    conn.commit()
    conn.close()

def create_table(cursor):
    # Here, write the SQL query to create your table, for example:
    cursor.execute(f'''
    CREATE TABLE {DB_TABLE_USER} (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        hashed_password TEXT,
        salt TEXT,
        role TEXT
    )
    ''')
    print(f"Table '{DB_TABLE_USER}' created successfully.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="My Python App")

    # Add the --enable-salting flag. The 'action' parameter is set to 'store_true', which means the corresponding variable will be set to True if the flag is provided.
    parser.add_argument("--enable-salting", help="Enable salting feature", action="store_true")
    parser.add_argument("--enable-cors", help="Enable CORS support", action="store_true")

    # Parse the command line arguments
    args = parser.parse_args()

    global use_salting
    global enable_cors
    use_salting = args.enable_salting
    enable_cors = args.enable_cors

    initialize_database(DB_NAME, DB_TABLE_USER)

    if os.path.exists(CERT_PEM_PATH) and os.path.exists(KEY_PEM_PATH):
        app.run(debug=True, port=2000, ssl_context=(CERT_PEM_PATH, KEY_PEM_PATH))
    else:
        print("Certificate and key not found, starting in HTTP mode.")
        app.run(debug=True, port=2000)