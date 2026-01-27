import struct
from typing import Any, Callable

from sstpd.constants import MsgType


class SSTPPacket:
    _version = 0x10

    def __init__(self, c: int, data: bytes = b"") -> None:
        self.c = c & 0x01
        self.data = data

    def write_to(self, func: Callable[[bytes], Any]) -> None:
        func(struct.pack("!BBH", self._version, self.c, len(self.data) + 4))
        func(self.data)


class SSTPDataPacket(SSTPPacket):
    def __init__(self, data: bytes) -> None:
        super().__init__(0, data)


class SSTPControlPacket(SSTPPacket):
    def __init__(
        self, message_type: MsgType, attributes: list[tuple[bytes, bytes]] = []
    ) -> None:
        super().__init__(1)
        self.message_type = message_type
        self.attributes = attributes

    def write_to(self, func: Callable[[bytes], Any]) -> Any:
        num_attribute = struct.pack("!H", len(self.attributes))
        self.data = self.message_type.value + num_attribute
        for attr_id, attr_value in self.attributes:
            length = struct.pack("!H", len(attr_value) + 4)
            self.data += b"\x00" + attr_id + length + attr_value
        return super().write_to(func)
