from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def write_pair(priv_name: str, pub_name: str):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(priv_name, "wb") as f:
        f.write(private_pem)
    with open(pub_name, "wb") as f:
        f.write(public_pem)

write_pair("issuer_private.pem", "issuer_public.pem")
write_pair("holder_private.pem", "holder_public.pem")
print("Generated issuer_*.pem and holder_*.pem")
