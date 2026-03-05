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
        # koga e izdaden
        "iat": now,
        # istekuvanje /// vaznosta na VCe 1 sat, za da ogranicam validitey period, kratko e zada se testira expiration logikata
        "exp": now + 3600
    }
    # enkodiranje so asimetricna kriptografija so sha256
    # jwt.encode kreira jwt token tuak so 3 dela(header(alritmot), payload(vc podatocie) i signature(privatniot kluc)
    # jwt strukturata e to header.payload.signature
    token = jwt.encode(vc_payload, PRIVATE_KEY, algorithm="ES256")
    return jsonify({"vc_jwt": token})

@app.get("/")
def home():
    return "Issuer is running. Use POST /issue"

if __name__ == "__main__":
    app.run(port=5001, debug=True)
