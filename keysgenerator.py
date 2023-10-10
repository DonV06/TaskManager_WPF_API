from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, asymmetric


def generate_rsa_keys():
    # Generate a private key
    private_key = asymmetric.rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generate a public key
    public_key = private_key.public_key()

    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save private key to a file
    with open('privatekey.pem', 'wb') as f:
        f.write(private_pem)

    # Save public key to a file
    with open('publickey.pem', 'wb') as f:
        f.write(public_pem)


# Generate the keys and save them
generate_rsa_keys()