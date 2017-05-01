import struct


class SSTPPacket:
    _version = 0x10

    def __init__(self, c, data=b''):
        self.c = c & 0x01
        self.data = data


    def write_to(self, func):
        func(struct.pack('!BBH', self._version, self.c, len(self.data) + 4))
        func(self.data)


class SSTPDataPacket(SSTPPacket):

    def __init__(self, data):
        super().__init__(0, data)


class SSTPControlPacket(SSTPPacket):

    def __init__(self, message_type, attributes=[]):
        super().__init__(1)
        self.message_type = message_type
        self.attributes = attributes

    def write_to(self, func):
        num_attribute = struct.pack('!H', len(self.attributes))
        self.data = self.message_type + num_attribute
        for attr_id, attr_value in self.attributes:
            length = struct.pack('!H', len(attr_value) + 4)
            self.data += b'\x00' + attr_id + length + attr_value
        return super().write_to(func)

