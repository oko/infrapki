import logging
import os
import shutil
import sys

import click
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from ..ca import CA
from ..sign import IntermediateCASignaturePolicy, ServerCertSignaturePolicy
from ..util import write_pem_certificate

log = logging.getLogger(__name__)


@click.group("ca")
def cacli():
    pass


@cacli.command("new")
@click.argument("directory")
@click.argument("config")
def new(directory, config):
    directory = os.path.realpath(directory)
    log.debug(f"real directory path is {directory}")

    if os.path.exists(directory):
        log.error(f"directory {directory} already exists")
        exit(1)

    # ensure no access from other users
    os.umask(0o077)

    ca = CA.new(directory, config)
    ca.initialize()


@cacli.command("sign")
@click.argument("directory")
@click.argument("csr")
@click.argument("output")
def sign(directory, csr, output):
    ca = CA(directory)
    if ca.is_root():
        policy = IntermediateCASignaturePolicy()
    else:
        policy = ServerCertSignaturePolicy()
    with open(csr, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read(), default_backend())
    cert = ca.sign(csr, policy)
    if cert is None:
        click.secho(
            "error signing certificate, see prior log messages",
            color="red",
            file=sys.stderr,
        )
        exit(1)
    write_pem_certificate(cert, output)
    print(f"{cert.serial_number:x}")
    print(f"{cert.subject.rfc4514_string()}")


@cacli.command("install-ca-cert")
@click.argument("directory")
@click.argument("cert")
def install_signed_ca_cert(directory, cert):
    ca = CA(directory)
    if ca.is_root():
        log.error(f"CA at {directory} is a root CA, cannot install cert")
        exit(1)
    shutil.copy(cert, ca.certificate_path())
