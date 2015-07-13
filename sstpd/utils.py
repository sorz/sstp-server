import struct


class hexdump(object):
    def __init__(self, s):
        self.s = s

    def __str__(self):
        return str(self.s).encode("hex")


def parseLength(s):
    s = chr(ord(s[0]) & 0x0f) + s[1]  # Ignore R
    return struct.unpack('!H', s)[0]

