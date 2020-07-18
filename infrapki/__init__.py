from typing import Optional, Union

from cryptography.hazmat.primitives.asymmetric import ec, rsa

KeyUnionType = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKeyWithSerialization]
