from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def new_rsa_key(key_size, public_exponent=65537, backend=None):
    if backend is None:
        backend = default_backend()
    return rsa.generate_private_key(
        public_exponent=public_exponent, key_size=key_size, backend=backend
    )


DEFAULT_ECDSA_KEY = ec.SECP256R1


def new_ecdsa_key(curve=None, backend=None):
    if curve is None:
        curve = DEFAULT_ECDSA_KEY
    if backend is None:
        backend = default_backend()

    return ec.generate_private_key(curve=curve, backend=backend)
