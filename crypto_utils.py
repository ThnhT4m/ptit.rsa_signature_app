from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


def generate_keys(private_key_path="keys/private_key.pem",
                  public_key_path="keys/public_key.pem",
                  password = None
                  ):
    if not password:
        raise ValueError("Password is required")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()
    password_bytes = password.encode("utf-8")

    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
            )
        )

    with open(public_key_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )


def load_private_key(path,password):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=password.encode("utf-8")
        )


def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def sign_data(data: bytes, private_key_path: str, password:str) -> bytes:
    private_key = load_private_key(private_key_path,password)

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def verify_signature(data: bytes, signature: bytes, public_key_path: str) -> bool:
    public_key = load_public_key(public_key_path)

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def read_file_bytes(file_path):
    with open(file_path, "rb") as f:
        return f.read()


def save_signature(signature: bytes, signature_path: str):
    with open(signature_path, "wb") as f:
        f.write(signature)


def read_signature(signature_path: str):
    with open(signature_path, "rb") as f:
        return f.read()