import base64
import hashlib
from typing import NamedTuple


PEM_BEGIN_MARK = b"-----BEGIN CERTIFICATE-----"
PEM_END_MARK = b"-----END CERTIFICATE-----"


class Fingerprint(NamedTuple):
    sha1: bytes
    sha256: bytes


def get_fingerprint(pem_path: str) -> Fingerprint:
    """Return (sha1, sha256) fingerprint of PEM cert."""
    lines = []
    with open(pem_path, "rb") as pem:
        for line in pem:
            if line.rstrip() == PEM_BEGIN_MARK:
                break
        for line in pem:
            if line.rstrip() == PEM_END_MARK:
                break
            lines.append(line.strip())
        if not lines:
            raise IOError("not a vaild PEM file")
    der = base64.decodebytes(b"".join(lines))
    sha1 = hashlib.sha1(der).digest()
    sha256 = hashlib.sha256(der).digest()
    return Fingerprint(sha1, sha256)
