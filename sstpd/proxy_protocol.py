from struct import unpack
from ipaddress import ip_address, AddressValueError


PP1_MAGIC = b'PROXY'
PP2_MAGIC = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'

PP2_CMD_LOCAL = 0x20
PP2_CMD_PROXY = 0x21
PP2_PROTO_TCP4 = 0x11
PP2_PROTO_TCP6 = 0x21

class PPException(Exception):
    pass

class PPNoEnoughData(PPException):
    pass

def parse_pp_header(data):
    """Support both version 1 and 2.
    Return (src_tuple, dest_tuple, remaining_data)"""
    if data.startswith(PP1_MAGIC):
        return parse_pp1_header(data)
    if data.startswith(PP2_MAGIC):
        return parse_pp2_header(data)
    if len(data) < len(PP2_MAGIC):
        raise PPNoEnoughData()
    raise PPException('PROXY PROTOCOL header not found')


def parse_pp1_header(data):
    """Return (src_tuple, dest_tuple, remaining_data)"""
    if len(data) < len(PP1_MAGIC):
        raise PPNoEnoughData()
    if not data.startswith(PP1_MAGIC):
        raise PPException('Not a PROXY PROTOCOL version 1 header.')
    if b'\r\n' not in data:
        if len(data) > 128:
            raise PPException('Not a valid PROXY PROTOCOL header.')
        raise PPNoEnoughData()
    header, remaining_data = data.split(b'\r\n', 1)
    try:
        _, family, src, dest, sport, dport = header.split()
        src = str(ip_address(src.decode()))
        dest = str(ip_address(dest.decode()))
        sport = int(sport)
        dport = int(dport)
    except ValueError:
        raise PPException('Not a valid/supported PROXY PROTOCOL header.')
    except AddressValueError:
        raise PPException('Illegal IP address on PROXY PROTOCOL.')
    return ((src, sport), (dest, dport), remaining_data)


def parse_pp2_header(data):
    """Return (src_tuple, dest_tuple, remaining_data),
    src & dest are None if local."""
    if len(data) < 16:
        raise PPNoEnoughData()
    if not data.startswith(PP2_MAGIC):
        raise PPException('Not a PROXY PROTOCOL version 2 header.')
    ver_cmd = ord(data[12])
    proto = ord(data[13])
    length, = unpack('!H', data[14:16])
    if len(data) < 16 + length:
        raise PPNoEnoughData()
    remaining_data = data[16 + length:]
    if ver_cmd == PP2_CMD_LOCAL:
        src = None
        dest = None
    elif ver_cmd == PP2_CMD_PROXY:
        if proto == PP2_PROTO_TCP4:
            src_ip, dest_ip, sport, dport = unpack('!4s4sHH', data[16:28])
        elif proto == PP2_PROTO_TCP6:
            src_ip, dest_ip, sport, dport = unpack('!16s16sHH', data[16:52])
        else:
            raise PPException('Underlying protocol not support.')
        src = (str(ip_address(src_ip)), sport)
        dest = (str(ip_address(dest_ip)), dport)
    else:
        raise PPException('PROXY PROTOCOL version or command not support.')
    return ((src, sport), (dest, dport), remaining_data)

