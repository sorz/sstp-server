from ipaddress import AddressValueError, ip_address
from struct import unpack
from typing import NamedTuple

PP1_MAGIC = b"PROXY"
PP2_MAGIC = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"

PP2_CMD_LOCAL = 0x20
PP2_CMD_PROXY = 0x21
PP2_PROTO_TCP4 = 0x11
PP2_PROTO_TCP6 = 0x21


class PPException(Exception):
    pass


class PPNoEnoughData(PPException):
    pass


class ProxyProtocolAddress(NamedTuple):
    ip: str
    port: int


class ProxyProtocolResult(NamedTuple):
    src: ProxyProtocolAddress | None
    dest: ProxyProtocolAddress | None
    remaining_data: bytearray


def parse_pp_header(data: bytearray) -> ProxyProtocolResult:
    """Support both version 1 and 2.
    Return (src_tuple, dest_tuple, remaining_data)"""
    if data.startswith(PP1_MAGIC):
        return parse_pp1_header(data)
    if data.startswith(PP2_MAGIC):
        return parse_pp2_header(data)
    if len(data) < len(PP2_MAGIC):
        raise PPNoEnoughData()
    raise PPException("PROXY PROTOCOL header not found")


def parse_pp1_header(data: bytearray) -> ProxyProtocolResult:
    """Return (src_tuple, dest_tuple, remaining_data)"""
    if len(data) < len(PP1_MAGIC):
        raise PPNoEnoughData()
    if not data.startswith(PP1_MAGIC):
        raise PPException("Not a PROXY PROTOCOL version 1 header.")
    if b"\r\n" not in data:
        if len(data) > 128:
            raise PPException("Not a valid PROXY PROTOCOL header.")
        raise PPNoEnoughData()
    header, remaining_data = data.split(b"\r\n", 1)
    try:
        parts = header.split()
        if len(parts) < 6:
            raise ValueError
        _, family, src_s, dest_s, sport_s, dport_s = parts
        src = str(ip_address(src_s.decode()))
        dest = str(ip_address(dest_s.decode()))
        sport = int(sport_s)
        dport = int(dport_s)
    except AddressValueError:
        raise PPException("Illegal IP address on PROXY PROTOCOL.")
    except ValueError:
        raise PPException("Not a valid/supported PROXY PROTOCOL header.")
    return ProxyProtocolResult(
        ProxyProtocolAddress(src, sport),
        ProxyProtocolAddress(dest, dport),
        bytearray(remaining_data),
    )


def parse_pp2_header(data: bytearray) -> ProxyProtocolResult:
    """Return (src_tuple, dest_tuple, remaining_data),
    src & dest are None if local."""
    if len(data) < 16:
        raise PPNoEnoughData()
    if not data.startswith(PP2_MAGIC):
        raise PPException("Not a PROXY PROTOCOL version 2 header.")
    ver_cmd = data[12]
    proto = data[13]
    (length,) = unpack("!H", data[14:16])
    if len(data) < 16 + length:
        raise PPNoEnoughData()
    remaining_data = data[16 + length :]

    src: ProxyProtocolAddress | None = None
    dest: ProxyProtocolAddress | None = None

    if ver_cmd == PP2_CMD_LOCAL:
        src = None
        dest = None
    elif ver_cmd == PP2_CMD_PROXY:
        if proto == PP2_PROTO_TCP4:
            src_ip, dest_ip, sport, dport = unpack("!4s4sHH", data[16:28])
            src = ProxyProtocolAddress(str(ip_address(src_ip)), sport)
            dest = ProxyProtocolAddress(str(ip_address(dest_ip)), dport)
        elif proto == PP2_PROTO_TCP6:
            src_ip, dest_ip, sport, dport = unpack("!16s16sHH", data[16:52])
            src = ProxyProtocolAddress(str(ip_address(src_ip)), sport)
            dest = ProxyProtocolAddress(str(ip_address(dest_ip)), dport)
        else:
            raise PPException("Underlying protocol not support.")
    else:
        raise PPException("PROXY PROTOCOL version or command not support.")
    return ProxyProtocolResult(src, dest, bytearray(remaining_data))
