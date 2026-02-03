import binascii


class hexdump:
    def __init__(self, s: bytes | memoryview) -> None:
        self.s = s

    def __str__(self) -> str:
        return binascii.hexlify(self.s).decode()

    def __repr__(self) -> str:
        return str(self)
