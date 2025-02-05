from flask import Flask, jsonify, request, session
from dotenv import load_dotenv
import os
from flask_bcrypt import Bcrypt
from flask_cors import CORS

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["https://jaimesoroa.github.io"])
bcrypt = Bcrypt(app)

# Secret Key for Session Management
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Dummy User Authentication
USERNAME = os.getenv("ADMIN_USERNAME")
PASSWORD_HASH = bcrypt.generate_password_hash(os.getenv("ADMIN_PASSWORD")).decode('utf-8')

@app.route('/')
def home():
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "accessToken": os.getenv("POWERBI_ACCESS_TOKEN"),
        "embedUrl": os.getenv("POWERBI_EMBED_URL"),
        "reportId": os.getenv("POWERBI_REPORT_ID")
    })

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Invalid request"}), 400

    if data["username"] == USERNAME and bcrypt.check_password_hash(PASSWORD_HASH, data["password"]):
        session["logged_in"] = True
        return jsonify({"message": "Login successful"})
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop("logged_in", None)
    return jsonify({"message": "Logged out"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)