from datetime import datetime, timedelta
from typing import Optional, Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import NameOID

from . import KeyUnionType


def gen_self_signed_root_ca_cert(subject: x509.Name, key: KeyUnionType):
    """
    Generate a self-signed root CA certificate

    :param subject:
    :param key:
    :return:
    """

    # self-issued
    issuer = subject

    # set exp dates and derive root CA serial from date of creation
    before = datetime.utcnow()
    serial = int(before.strftime("%Y%m%d"))
    after = before + timedelta(days=365 * 20)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(before)
        .not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    return cert
