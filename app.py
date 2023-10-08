from flask import Flask, request, jsonify
import os
import hashlib
import argparse
import base64
from datetime import datetime, timedelta

app = Flask(__name__)

users_db = {}

CERT_PEM_PATH = 'certificate/cert.pem'
KEY_PEM_PATH = 'certificate/key.pem'
JWT_SIG_KEY = os.urandom(24).hex()
SALT_LENGTH = 16

# scrypt parameters
N = 16384 # CPU/memory cost factor. Must be a power of 2.
R = 8     # Block size
P = 1     # Parallelization factor

@app.route('/')
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
        return jsonify({'message': 'Login successful.', 'token': 'your_generated_token'}), 200
    else:
        return jsonify({'message': 'Incorrect password.'}), 401

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

# Helper functions for  jwt functions
def base64UrlEncode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')

def base64UrlDecode(base64Url):
    padding = b'=' * (4 - (len(base64Url) % 4))
    return base64.urlsafe_b64decode(base64Url + padding)