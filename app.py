from flask import Flask, request, jsonify
import os
import hashlib

app = Flask(__name__)


users_db = {}

CERT_PEM_PATH = 'certificate/cert.pem'
KEY_PEM_PATH = 'certificate/key.pem'

@app.route('/')
def hello():
    return "hello world"

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Username and password are required.'}), 400
    
    username = data['username']
    password = data['password']
    

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    if username in users_db:
        return jsonify({'message': 'Username already exists.'}), 400
    
    users_db[username] = hashed_password
    
    return jsonify({'message': 'Registration successful.'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Username and password are required.'}), 400
    
    username = data['username']
    password = data['password']
    
    if username not in users_db:
        return jsonify({'message': 'Username not found.'}), 401
    
    stored_password = users_db[username]
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    if stored_password == hashed_password:
        return jsonify({'message': 'Login successful.', 'token': 'your_generated_token'}), 200
    else:
        return jsonify({'message': 'Incorrect password.'}), 401

if __name__ == '__main__':
    if os.path.exists(CERT_PEM_PATH) and os.path.exists(KEY_PEM_PATH):
        app.run(debug=True, port=2000, ssl_context=(CERT_PEM_PATH, KEY_PEM_PATH))
    else:
        print("Certificate and key not found, starting in HTTP mode.")
        app.run(debug=True, port=2000)

