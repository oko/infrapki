import abc

from cryptography import x509, exceptions
from cryptography.x509 import extensions as x509ext
from cryptography.x509 import oid


class SignaturePolicyResult(object):
    def __init__(self, errors):
        self.errors = errors

    def ok(self):
        return len(self.errors) == 0


class SignaturePolicy(abc.ABC):
    @abc.abstractmethod
    def validate_csr(
        self, csr: x509.CertificateSigningRequest
    ) -> SignaturePolicyResult:
        pass

    @abc.abstractmethod
    def build_cert(
        self, cacert: x509.Certificate, csr: x509.CertificateSigningRequest
    ) -> x509.CertificateBuilder:
        pass


class ServerCertSignaturePolicy(SignaturePolicy):
    def __init__(self):
        pass

    def validate_csr(
        self, csr: x509.CertificateSigningRequest
    ) -> SignaturePolicyResult:
        errors = []
        try:
            basic = csr.extensions.get_extension_for_class(x509.BasicConstraints)
            if basic.value.ca:
                errors.append(
                    ValueError(
                        "BasicConstraints.CA must not be true for server certificates"
                    )
                )
        except x509ext.ExtensionNotFound:
            pass
        return SignaturePolicyResult(errors)

    def build_cert(
        self, cacert: x509.Certificate, csr: x509.CertificateSigningRequest
    ) -> x509.CertificateBuilder:
        return (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(cacert.subject)
            .public_key(csr.public_key())
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None,), critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(cacert.public_key()),
                critical=False,
            )
        )


class IntermediateCASignaturePolicy(SignaturePolicy):
    def __init__(self, ca_path_length=0):
        self.ca_path_length = ca_path_length

    def validate_csr(
        self, csr: x509.CertificateSigningRequest
    ) -> SignaturePolicyResult:
        errors = []
        return SignaturePolicyResult(errors)

    def build_cert(
        self, cacert: x509.Certificate, csr: x509.CertificateSigningRequest
    ) -> x509.CertificateBuilder:
        return (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(cacert.subject)
            .public_key(csr.public_key())
            .add_extension(
                x509.BasicConstraints(
                    ca=True,
                    path_length=(
                        self.ca_path_length - 1 if self.ca_path_length > 0 else 0
                    ),
                ),
                critical=True,
            )
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
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(cacert.public_key()),
                critical=False,
            )
        )
