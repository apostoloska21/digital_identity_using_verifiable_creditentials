from flask import Flask, request, jsonify
import jwt, time
from pathlib import Path
app = Flask(__name__)

with open("issuer_private.pem", "rb") as f:
    PRIVATE_KEY = f.read()


@app.post("/issue")
def issue():
    data = request.get_json(force=True)
    now = int(time.time())

    vc_payload = {
        "type": "StudentIDCredential",
        "studentId": data["studentId"],
        "fullName": data["fullName"],
        "faculty": data["faculty"],
        "iat": now,
        "exp": now + 3600
    }

    token = jwt.encode(vc_payload, PRIVATE_KEY, algorithm="ES256")
    return jsonify({"vc_jwt": token})

@app.get("/")
def home():
    return "Issuer is running. Use POST /issue"

if __name__ == "__main__":
    app.run(port=5001, debug=True)
