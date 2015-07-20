import struct


class hexdump(object):
    def __init__(self, s):
        self.s = s

    def __str__(self):
        return str(self.s).encode("hex")



