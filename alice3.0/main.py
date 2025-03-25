import time
import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import Aer
from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId
from bson import json_util
from hybrid_crypto import hybrid_encrypt
from hybrid_crypto import hybrid_decrypt
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import requests
from datetime import timedelta
from flask_cors import CORS


def key_gen():
    # Step 1: Define number of qubits for the key length
    key_length = 100  # Adjust this value for a longer or shorter key
    # Alice's random bits (0 or 1)
    alice_bits = np.random.randint(2, size=key_length)
    # Alice's random bases (0 or 1 for rectilinear or diagonal)
    alice_bases = np.random.randint(2, size=key_length)

    # Step 2: Initialize the Aer simulator
    simulator = Aer.get_backend('qasm_simulator')
    alice_key = []

    # Step 3: Alice prepares and sends qubits based on her random bits and bases
    start_time = time.time()  # Start timing key generation
    for i in range(key_length):
        # Create a single qubit circuit
        qc = QuantumCircuit(1, 1)

        # Prepare qubit in the basis chosen by Alice
        if alice_bases[i] == 0:  # Rectilinear basis
            if alice_bits[i] == 1:
                qc.x(0)  # Apply X gate to set to |1>
        else:  # Diagonal basis
            if alice_bits[i] == 1:
                qc.x(0)
            qc.h(0)  # Apply H gate for diagonal basis

        qc.measure(0, 0)

        # Run the circuit
        result = simulator.run(qc, shots=1).result()
        measurement = int(list(result.get_counts().keys())[0])  # Get the measurement outcome

        alice_key.append(int(alice_bits[i]))
    end_time = time.time()  # End timing key generation
    
    key_gen_time = end_time - start_time
    print(f"Key generation time: {key_gen_time:.6f} seconds")
    
    return alice_key, alice_bases, key_gen_time


app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
app.config['JWT_SECRET_KEY'] = 'alice_to_bob_co@#$$'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
jwt = JWTManager(app)

# MongoDB user collection
client = MongoClient("mongodb://localhost:27017/")  # Update with your MongoDB connection string
db = client['quantum_security']
collection = db['encrypted_data']
users_collection = db['users']


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = users_collection.find_one({'email': email})
    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify({'error': 'Invalid email or password'}), 401

    access_token = create_access_token(identity=email)
    return jsonify({'access_token': access_token}), 200


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if users_collection.find_one({'email': email}):
        return jsonify({'error': 'User already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    users_collection.insert_one({'email': email, 'password': hashed_password})
    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/share_key', methods=['POST'])
def alice_key():
    request_data = request.get_json()
    bob_bits = request_data["bits"]
    bob_bases = request_data["bases"]
    alice_bits, alice_bases, key_gen_time = key_gen()
    shared_key = []

    for i in range(len(alice_bits)):
        if alice_bases[i] == bob_bases[i]:
            shared_key.append(bob_bits[i])
    
    return jsonify({
        'shared_key': shared_key,
        'key_gen_time': key_gen_time  # Include key generation time in the response
    })


@app.route('/send', methods=['POST'])
@jwt_required()
def encrypt():
    try:
        # Retrieve data from the POST request
        request_data = request.get_json()
        data = request_data.get('data', '')
        current_user = get_jwt_identity()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Convert data to bytes
        data = data.encode('utf-8')

        # Generate a BB84 shared key
        url = 'http://127.0.0.1:6000/share_key'
        bits, bases, key_gen_time = key_gen()
        key = {
            "bits": bits,
            "bases": bases.tolist()
        }
        response = requests.post(url, json=key)
        res = response.json()
        bb84_shared_key = res["shared_key"]

        # Measure encryption time
        start_time = time.time()
        encrypted_result = hybrid_encrypt(data, bb84_shared_key)
        encryption_time = time.time() - start_time
        print(f"Encryption time: {encryption_time:.6f} seconds")

        # Convert BB84 shared key and encrypted data to hex for storage
        bb84_key_hex = ''.join(map(str, bb84_shared_key))
        encrypted_data_hex = encrypted_result.hex()

        # Store in MongoDB
        record = {
            'bb84_shared_key': bb84_key_hex,
            'encrypted_data': encrypted_data_hex,
            'user': current_user
        }
        collection.insert_one(record)

        return jsonify({
            'message': 'Data successfully encrypted and stored in MongoDB.',
            'record_id': str(record['_id']),
            'key_gen_time': key_gen_time,
            'encryption_time': encryption_time
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/retrieve', methods=['POST'])
@jwt_required()
def retrieve():
    try:
        request_data = request.get_json()
        record_id = request_data.get('record_id')
        current_user = get_jwt_identity()

        if not record_id:
            return jsonify({'error': 'No record ID provided'}), 400

        # Fetch the record from MongoDB
        record = collection.find_one({'_id': ObjectId(record_id)})
        if not record:
            return jsonify({'error': 'Record not found'}), 404

        # Extract data from the record
        bb84_shared_key_hex = record['bb84_shared_key']
        encrypted_data_hex = record['encrypted_data']

        # Convert BB84 shared key and encrypted data back to original formats
        bb84_shared_key = [int(bit) for bit in bb84_shared_key_hex]
        encrypted_data = bytes.fromhex(encrypted_data_hex)

        # Measure decryption time
        start_time = time.time()
        decrypted_data = hybrid_decrypt(encrypted_data, bb84_shared_key)
        decryption_time = time.time() - start_time
        print(f"Decryption time: {decryption_time:.6f} seconds")

        return jsonify({
            'message': 'Data successfully decrypted.',
            'original_data': decrypted_data.decode('utf-8'),
            'decryption_time': decryption_time
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
