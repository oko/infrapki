from dataclasses import dataclass, field
from typing import Any, Dict

from cryptography import x509
from cryptography.x509 import NameOID


def dict_to_name(data: Dict[str, str]):
    attrs = []
    for k, v in data.items():
        oid = getattr(NameOID, k.upper())
        attrs.append(x509.NameAttribute(oid, v))
    return x509.Name(attrs)
