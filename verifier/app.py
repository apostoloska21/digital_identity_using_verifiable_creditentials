from flask import Flask, request, jsonify, render_template
import jwt, time, secrets

app = Flask(__name__)

ISSUER_PUBLIC = open("issuer_public.pem", "rb").read()


NONCES = {}  # nonce -> exp timestamp

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/challenge")
def challenge():
    ttl = 600
    nonce = secrets.token_urlsafe(16)
    exp = int(time.time()) + ttl
    NONCES[nonce] = exp
    return jsonify({"nonce": nonce, "expiresIn": ttl})


@app.post("/verify")
def verify():
    data = request.get_json(force=True)
    vp_jwt = data["vp_jwt"]
    holder_public_pem = data["holder_public_key_pem"].encode()

    # 1) verify VP signature (holder)
    vp = jwt.decode(vp_jwt, holder_public_pem, algorithms=["ES256"])

    # 2) nonce check (anti-replay)
    nonce = vp.get("nonce")
    if not nonce or nonce not in NONCES:
        return jsonify({"valid": False, "error": "Missing/unknown nonce"}), 400
    if NONCES[nonce] < int(time.time()):
        return jsonify({"valid": False, "error": "Expired nonce"}), 400
    del NONCES[nonce]

    # 3) verify embedded VC signature (issuer)
    vc_jwt = vp["vc_jwt"]
    vc = jwt.decode(vc_jwt, ISSUER_PUBLIC, algorithms=["ES256"])

    if vc.get("type") != "StudentIDCredential":
        return jsonify({"valid": False, "error": "Wrong VC type"}), 400

    return jsonify({"valid": True, "vc_payload": vc})

if __name__ == "__main__":
    app.run(port=5004, debug=True)
