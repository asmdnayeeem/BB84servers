from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId
from hybrid_crypto import hybrid_decrypt

# Initialize Flask app
app = Flask(__name__)

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")  # Update with your MongoDB connection string
db = client['quantum_security']
collection = db['encrypted_data']

@app.route('/retrieve', methods=['POST'])
def retrieve():
    try:
        # Retrieve record ID from the request
        request_data = request.get_json()
        record_id = request_data.get('record_id')

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
    app.run(debug=True, port=5001)  # Receiver runs on a different port
