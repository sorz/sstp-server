import struct

from hexdump import hexdump


class SSTPPacket(object):
    _version = '\x10'

    def __init__(self, c, data=''):
        self.c = c
        self.data = data


    def dump(self):
        length = struct.pack('!H', len(self.data) + 4)
        c = chr(self.c & 0x01)
        return self._version + c + length + self.data


class SSTPDataPacket(SSTPPacket):

    def __init__(self, data):
        super(SSTPDataPacket, self).__init__(0, data)


class SSTPControlPacket(SSTPPacket):

    def __init__(self, message_type, attributes=[]):
        super(SSTPControlPacket, self).__init__(1)
        self.message_type = message_type
        self.attributes = attributes


    def dump(self):
        num_attribute = struct.pack('!H', len(self.attributes))
        self.data = self.message_type + num_attribute
        for attr_id, attr_value in self.attributes:
            length = struct.pack('!H', len(attr_value) + 4)
            self.data += '\x00' + attr_id + length + attr_value 
        return super(SSTPControlPacket, self).dump()

