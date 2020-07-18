import logging
import os
import shutil
from datetime import datetime, timedelta
from typing import Optional, Union

import click
import toml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .certgen import gen_self_signed_root_ca_cert
from .csrgen import gen_int_ca_csr
from .db import Base, IssuedCert
from .keygen import new_ecdsa_key, new_rsa_key
from .sign import IntermediateCASignaturePolicy, SignaturePolicy, SignaturePolicyResult
from .subject import dict_to_name
from .util import serial_number_to_bytes

log = logging.getLogger(__name__)


class CAPrivateKeyAlreadyExistsError(BaseException):
    pass


class CACertificateSigningRequestPendingError(BaseException):
    pass


class CACertificateAlreadyExistsError(BaseException):
    pass


class CA(object):
    @staticmethod
    def new(directory, config):
        ca = CA.__new__(CA)
        ca.dir = directory
        os.umask(0o077)
        os.makedirs(ca.dir, mode=0o0700, exist_ok=True)
        shutil.copy(config, ca.config_path())
        os.makedirs(ca.private_dir(), mode=0o0700, exist_ok=True)
        os.makedirs(ca.public_dir(), mode=0o0700, exist_ok=True)
        return CA(directory)

    def __init__(self, directory, new=False):
        self.dir = os.path.realpath(directory)
        self.config = self.load_config()
        self.db = None
        self.db_session = None

        self.db = create_engine(f"sqlite:///{self.db_path()}")
        Base.metadata.create_all(self.db)
        self.db_session = sessionmaker(bind=self.db)

    def config_path(self):
        return os.path.join(self.dir, "infrapki.ca.toml")

    def public_dir(self):
        return os.path.join(self.dir, "public")

    def private_dir(self):
        return os.path.join(self.dir, "private")

    def certs_dir(self):
        return os.path.join(self.dir, "certs")

    def private_key_path(self):
        return os.path.join(self.private_dir(), "ca.key.pem")

    def certificate_path(self):
        return os.path.join(self.public_dir(), "ca.cert.pem")

    def csr_path(self):
        return os.path.join(self.public_dir(), "ca.csr.pem")

    def is_root(self):
        return self.config["ca"].get("root", False)

    def db_path(self):
        return os.path.join(self.dir, "db.sqlite3")

    def get_passphrase(self):
        """
        Helper function to fetch a passphrase from user if configuration does
        not specify "no passphrase"

        :return: passphrase bytes (or None if no passphrase)
        """
        if self.config["ca"].get("private_key_no_passphrase", False):
            return None
        else:
            data = click.prompt("enter CA key passphrase", hide_input=True, type=bytes)
            if not data:
                raise ValueError(
                    "must specify private_key_no_passphrase in CA configuration"
                )
            return data

    def initialize(self):
        """
        Initialize the CA

        :return:
        """
        key = None
        passphrase = None

        # generate and load the private key if necessary
        if not os.path.exists(self.private_key_path()):
            log.info("private key file does not exist, generating")
            key = self.generate_private_key()
            passphrase = self.get_passphrase()
            self.write_private_key(key, passphrase)
            log.info("generated private key file")
        else:
            log.warning("private key file already exists, not regenerating")

        if self.config["ca"].get("root", False):
            log.info("this CA is a root CA, generating certificate")
            if not os.path.exists(self.certificate_path()):
                log.info("certificate file does not exist, generating")
                if key is None:
                    if passphrase is None:
                        passphrase = self.get_passphrase()
                    key = self.load_private_key(passphrase)
                log.debug("loaded private key successfully")
                cert = self.generate_ca_cert(key)
                self.write_ca_cert(cert)
                log.info("generated certificate file")
            else:
                log.warning("certificate file already exists, not regenerating")
        else:
            log.info("this CA is an intermediate CA, generating CSR for signing")
            if not os.path.exists(self.csr_path()):
                log.info("CSR does not exist yet")
                if key is None:
                    if passphrase is None:
                        passphrase = self.get_passphrase()
                    key = self.load_private_key(passphrase)
                csr = self.generate_ca_csr(key)
                self.write_ca_csr(csr)
            else:
                log.info("CSR already exists")
                if not os.path.exists(self.certificate_path()):
                    raise CACertificateSigningRequestPendingError(
                        f"CSR in {self.csr_path()} is pending certificate signing and placement in {self.certificate_path()}"
                    )
                else:
                    log.info("intermediate CA certificate already exists")

    def generate_private_key(self):
        """
        Generate the CA private key (configured via [ca] config section)
        :return:
        """
        algo = self.config["ca"].get("private_key_algorithm", rsa)
        rsa_key_size = self.config["ca"].get("private_key_size", 4096)
        if algo == "rsa":
            pk = new_rsa_key(rsa_key_size)
        elif algo == "ecdsa":
            pk = new_ecdsa_key()
        elif algo == "secp256r1":
            pk = new_ecdsa_key(curve=ec.SECP256R1)
        else:
            raise ValueError(f"invalid key algorithm in config: {algo}")
        return pk

    def write_private_key(
        self,
        pk: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKeyWithSerialization],
        passphrase: bytes,
    ):
        """
        Write the CA private key file

        :param pk: private key object
        :param passphrase: passphrase to encrypt the private key file with
        :return:
        """
        if os.path.exists(self.private_key_path()):
            raise CAPrivateKeyAlreadyExistsError(self.private_key_path())

        if not passphrase:
            enc = serialization.NoEncryption()
        else:
            enc = serialization.BestAvailableEncryption(passphrase)
        with open(self.private_key_path(), "wb") as f:
            f.write(
                pk.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=enc,
                )
            )

    def load_private_key(self, passphrase: Optional[bytes] = None):
        """
        Load the private key for this CA

        :param passphrase: the passphrase to use to load the private key
        :return:
        """
        with open(self.private_key_path(), "rb") as f:
            if not passphrase:
                passphrase = None
            return serialization.load_pem_private_key(
                f.read(), passphrase, default_backend()
            )

    def load_ca_cert(self) -> x509.Certificate:
        with open(self.certificate_path(), "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())

    def generate_ca_cert(self, key):
        """
        Generate the CA certificate for this CA
        :param key: the private key to use for certificate signing
        :return:
        """
        log.info(f"generating CA certificate in {self.certificate_path()}")
        subject = dict_to_name(self.config["ca"]["subject_name"])

        cert = gen_self_signed_root_ca_cert(subject, key)
        log.debug("generated self-signed root CA certificate successfully")

        return cert

    def write_ca_cert(self, cert: x509.Certificate):
        """
        Write the CA certificate for this CA
        :param cert: the certificate to write
        :return:
        """
        with open(self.certificate_path(), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        log.debug("wrote self-signed root CA certificate successfully")

    def install_ca_cert(self, to_inst: str):
        if os.path.exists(self.certificate_path()):
            raise ValueError
        else:
            with open(to_inst, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            with open(self.csr_path()) as f:
                csr = x509.load_pem_x509_csr(f.read(), default_backend())
            assert csr.public_key() == cert.public_key()
            shutil.copy(to_inst, self.certificate_path())

    def generate_ca_csr(self, key):
        """
        Generate the CA certificate signing request (for intermediates)

        :param key: private key to use for signing the CSR
        :return:
        """
        subject = dict_to_name(self.config["ca"]["subject_name"])
        pathlen = self.config["ca"].get("max_path_length", None)
        csr = gen_int_ca_csr(subject, key, pathlen)
        return csr

    def write_ca_csr(self, csr: x509.CertificateSigningRequest):
        """
        Write the CA certificate signing request (for intermediates)
        :param csr:
        :return:
        """
        with open(self.csr_path(), "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

    def sign(
        self, csr: x509.CertificateSigningRequest, policy: SignaturePolicy
    ) -> Optional[x509.Certificate]:
        res = policy.validate_csr(csr)
        if not res.ok():
            log.error(f"failed to validate CSR against policy {policy}")
            for err in res.errors:
                log.error(f"error: {err}")
            return None

        passphrase = self.get_passphrase()
        key = self.load_private_key(passphrase)

        before = datetime.now()
        after = datetime.now() + timedelta(days=30)
        certbuild = (
            policy.build_cert(self.load_ca_cert(), csr)
            .serial_number(x509.random_serial_number())
            .not_valid_before(before)
            .not_valid_after(after)
        )
        cert = certbuild.sign(key, hashes.SHA256(), default_backend())

        session: Session = self.db_session()
        ic = IssuedCert(
            serial=serial_number_to_bytes(cert.serial_number),
            cert=cert.public_bytes(serialization.Encoding.PEM),
        )
        session.add(ic)
        print("serial:", ic.serial)
        session.commit()

        return cert

    def load_config(self):
        with open(self.config_path()) as f:
            return toml.load(f)
