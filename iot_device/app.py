from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/message', methods=['POST'])
def handle_message():
    """
    Handle incoming messages.
    Expects a JSON payload with 'ip' and 'message'.
    """
    data = request.get_json()
    if not data or 'ip' not in data or 'message' not in data:
        return jsonify({"error": "Invalid request. 'ip' and 'message' are required."}), 400

    ip = data['ip']
    message = data['message']
    print(f"Received message from {ip}: {message}")

    # Placeholder response
    return jsonify({"status": "Message received"}), 200

@app.route('/status', methods=['GET'])
def check_status():
    """
    Respond with a status message indicating the IoT node is alive.
    """
    return jsonify({"status": "IoT node is alive"}), 200

if __name__ == '__main__':
    # Run the Flask app on port 5000
    app.run(host='0.0.0.0', port=5000)
