import binascii

class hexdump:
    def __init__(self, s):
        self.s = s

    def __str__(self):
        return binascii.hexlify(self.s).decode()

    def __repr__(self):
        return str(self)
