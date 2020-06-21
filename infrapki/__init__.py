from cryptography.hazmat.primitives.asymmetric import rsa, ec
from typing import Union, Optional

KeyUnionType = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKeyWithSerialization]
