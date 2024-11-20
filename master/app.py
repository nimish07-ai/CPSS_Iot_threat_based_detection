from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/contact', methods=['POST'])
def relay_message():
    """
    Relays a message from one IoT node to another via the master node.
    Expects JSON payload with 'target_ip' and 'message'.
    """
    data = request.get_json()
    if not data or 'target_ip' not in data or 'message' not in data:
        return jsonify({"error": "Invalid request. 'target_ip' and 'message' are required."}), 400

    target_ip = data['target_ip']
    message = data['message']
    target_url = f"http://{target_ip}:5000/message"

    try:
        # Relay the message to the target IoT node
        response = requests.post(target_url, json={"ip": request.remote_addr, "message": message})
        return jsonify({"status": "Message relayed", "response_from_target": response.json()}), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to contact target node: {e}"}), 500


@app.route('/status_of_node', methods=['POST'])
def curl():
    # Get the URL from the form data
    url = request.form.get("ip")
    
    # Log the URL for debugging purposes
    app.logger.info(f"Received URL to curl: {url}")

    # Prepare the curl command
    command = f"curl {url}"
    print("command ",command)

    try:
        # Run the curl command
        output = subprocess.check_output(command, shell=True, text=True)
        app.logger.info(f"Curl output: {output}")
        return jsonify({"status": "success", "message": "Curl request successful", "url": url, "output": output}), 200
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Error during curl command execution: {str(e)}")
        return jsonify({"status": "error", "message": "Error with curl request", "error": str(e)}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"status": "error", "message": "Unexpected error occurred", "error": str(e)}), 500



if __name__ == '__main__':
    # Run the Flask app on port 5000
    app.run(host='0.0.0.0', port=5000)