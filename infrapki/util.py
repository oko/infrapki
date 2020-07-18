from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def write_pem_certificate(cert: x509.Certificate, path: str) -> None:
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def serial_number_to_bytes(x) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder="big")
