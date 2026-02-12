from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)

with open("issuer_public.pem", "rb") as f:
    PUBLIC_KEY = f.read()

@app.post("/verify")
def verify():
    data = request.get_json(force=True)
    token = data["vc_jwt"]

    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=["ES256"])
        if payload.get("type") != "StudentIDCredential":
            return jsonify({"valid": False, "error": "Wrong type"}), 400
        return jsonify({"valid": True, "payload": payload})
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)}), 400

if __name__ == "__main__":
    app.run(port=5003, debug=False)
