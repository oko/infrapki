from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from . import KeyUnionType


def gen_int_ca_csr(subject: x509.Name, key: KeyUnionType, pathlen: int):
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=pathlen), critical=True
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    return csr
