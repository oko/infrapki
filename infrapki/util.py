from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


def write_pem_certificate(cert: x509.Certificate, path: str) -> None:
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
