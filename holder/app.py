from flask import Flask, request, jsonify, render_template
import jwt, time, json, os
import requests

app = Flask(__name__)

HOLDER_PRIVATE = (open("holder_private.pem", "rb")).read()
HOLDER_PUBLIC = (open("holder_public.pem", "rb")).read()

WALLET_FILE = "wallet.json"
if not os.path.exists(WALLET_FILE):
    with open(WALLET_FILE, "w") as f:
        json.dump({"vcs": []}, f)

@app.get("/")
def index():
    with open(WALLET_FILE, "r") as f:
        wallet = json.load(f)
    return render_template("index.html", vcs=wallet["vcs"])

@app.post("/store")
def store():
    data = request.get_json(force=True)
    vc_jwt = data["vc_jwt"]

    with open(WALLET_FILE, "r") as f:
        wallet = json.load(f)
    wallet["vcs"].append(vc_jwt)
    with open(WALLET_FILE, "w") as f:
        json.dump(wallet, f, indent=2)

    return jsonify({"stored": True, "count": len(wallet["vcs"])})

@app.post("/present")
def present():
    data = request.get_json(force=True)
    vc_jwt = data["vc_jwt"]

    # Get challenge (nonce) from verifier
    ch = requests.get("http://127.0.0.1:5004/challenge").json()
    nonce = ch["nonce"]

    now = int(time.time())
    vp_payload = {
        "type": "StudentIDPresentation",
        "vc_jwt": vc_jwt,
        "nonce": nonce,
        "iat": now,
        "exp": now + 300
    }

    vp_jwt = jwt.encode(vp_payload, HOLDER_PRIVATE, algorithm="ES256")
    return jsonify({"vp_jwt": vp_jwt, "holder_public_key_pem": HOLDER_PUBLIC.decode()})

if __name__ == "__main__":
    app.run(port=5002, debug=True)
