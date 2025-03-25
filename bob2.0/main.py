import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import Aer
from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId
from hybrid_crypto import hybrid_decrypt
from hybrid_crypto import hybrid_encrypt
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import requests   
from datetime import timedelta
from flask_cors import CORS

def key_gen():
    # Step 1: Define number of qubits for the key length
    key_length = 100  # Adjust this value for a longer or shorter key
    bob_bases = np.random.randint(2, size=key_length)    # Bob's random bases (0 or 1 for rectilinear or diagonal)
    # Step 2: Initialize the Aer simulator
    simulator = Aer.get_backend('qasm_simulator')
    bob_key = []
    # Step 3: Bob generates the qubits
    for i in range(key_length):
        # Create a single qubit circuit
        qc = QuantumCircuit(1, 1)
        
        # # Step 4: Bob measures in his chosen basis
        if bob_bases[i] == 1:
            qc.h(0)  # If Bob's basis is diagonal, apply H before measurement
        
        qc.measure(0, 0)
        # Run the circuit
        result = simulator.run(qc, shots=1).result()
        measurement = int(list(result.get_counts().keys())[0])  # Get the measurement outcome
        bob_key.append(measurement)

    return bob_key,bob_bases
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['JWT_SECRET_KEY'] = 'alice_to_bob_co@#$$'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
jwt = JWTManager(app)
CORS(app)
# MongoDB connection
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

@app.route('/share_key',methods=['POST'])
def bob_key():
    request_data=request.get_json()
    # print(request_data)
    alice_bits=request_data["bits"]
    alice_bases=request_data["bases"]
    bob_bits,bob_bases=key_gen()
    # print(
    #     {
    #         "bits":bob_bits,
    #         "bases":bob_bases
    #     })
    skey=[]
    for i in range(len(alice_bits)):
        if alice_bases[i] == bob_bases[i]:
            skey.append(bob_bits[i])
    # print(skey)
    return jsonify({
        'shared_key':skey
    })

@app.route('/send', methods=['POST'])
@jwt_required()
def encrypt():
    try:
        # Retrieve data from the POST request
        request_data = request.get_json()
        data = request_data.get('data', '')
        current_user = get_jwt_identity()
        print(f"Data encryption requested by: {current_user}")

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Convert data to bytes
        data = data.encode('utf-8')

        url = 'http://127.0.0.1:5000/share_key'
        bits,bases=key_gen()
        bases=bases.tolist()
        key={
            "bits":bits,
            "bases":bases
        }
        response = requests.post(url, json=key)
        res=response.json()
        bb84_shared_key = res["shared_key"]  # Replace with actual implementation
        # Encrypt the data using the BB84 shared key
        encrypted_result = hybrid_encrypt(data, bb84_shared_key)

        # Convert BB84 shared key and encrypted data to hex for storage
        bb84_key_hex = ''.join(map(str, bb84_shared_key))
        encrypted_data_hex = encrypted_result.hex()

        # Store in MongoDB
        record = {
            'bb84_shared_key': bb84_key_hex,
            'encrypted_data': encrypted_data_hex,
            'user':current_user
        }
        collection.insert_one(record)

        return jsonify({
            'message': 'Data successfully encrypted and stored in MongoDB.',
            'record_id': str(record['_id'])  # MongoDB document ID
        }), 200

    except Exception as e:
        return jsonify({'error': e}), 500

@app.route('/retrieve', methods=['POST'])
@jwt_required()
def retrieve():
    try:
        # Retrieve record ID from the request
        request_data = request.get_json()
        record_id = request_data.get('record_id')
        current_user = get_jwt_identity()
        print(f"Data decryption requested by: {current_user}")

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

        # Decrypt the data using the BB84 shared key
        decrypted_data = hybrid_decrypt(encrypted_data, bb84_shared_key)

        return jsonify({
            'message': 'Data successfully decrypted.',
            'original_data': decrypted_data.decode('utf-8')
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6000,debug=True)
