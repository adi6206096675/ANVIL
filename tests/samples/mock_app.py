# tests/samples/mock_app.py
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/v1/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    email = data.get("email")

    # 1. Type validation check
    if not isinstance(username, str):
        return jsonify({"error": "Username must be a string"}), 400

    # 2. Required parameter check
    if not username or not email:
        return jsonify({"error": "Missing required fields"}), 422

    # 3. Boundary length check
    if len(username) > 256:
        return jsonify({"error": "Username exceeds length limit"}), 400

    return jsonify({"message": "User registered successfully"}), 200

if __name__ == "__main__":
    print("[MOCK SERVER] Running target API on http://127.0.0.1:5000...")
    app.run(port=5000)