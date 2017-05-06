class SimpleEnumMeta(type):
    """Metaclass. Add a dict `str` to allow looking up class's attribute name
    by its value. Ideal for debugging.
    """
    def __new__(meta, name, bases, attrs):
        attrs['str'] = { v: k for k, v in attrs.items()
                         if not k.startswith('_') }
        return super(SimpleEnumMeta, meta).__new__(meta, name, bases, attrs)

# Log level
VERBOSE = 5

## Protocol related constants

# Message Type
class MsgType(metaclass=SimpleEnumMeta):
    CALL_CONNECT_REQUEST = b'\x00\x01'
    CALL_CONNECT_ACK = b'\x00\x02'
    CALL_CONNECT_NAK = b'\x00\x03'
    CALL_CONNECTED = b'\x00\x04'
    CALL_ABORT = b'\x00\x05'
    CALL_DISCONNECT = b'\x00\x06'
    CALL_DISCONNECT_ACK = b'\x00\x07'
    ECHO_REQUEST = b'\x00\x08'
    ECHO_RESPONSE = b'\x00\x09'

# Attribute ID
SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID = b'\x01'
SSTP_ATTRIB_STATUS_INFO = b'\x02'
SSTP_ATTRIB_CRYPTO_BINDING = b'\x03'
SSTP_ATTRIB_CRYPTO_BINDING_REQ = b'\x04'

# Protocol ID
SSTP_ENCAPSULATED_PROTOCOL_PPP = b'\x00\x01'

# Hash Protocol Bitmask
CERT_HASH_PROTOCOL_SHA1 = b'\x01'
CERT_HASH_PROTOCOL_SHA256 = b'\x02'

# AttribID
SSTP_ATTRIB_NO_ERROR = b'\x00'
SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID = b'\x01'
SSTP_ATTRIB_STATUS_INFO = b'\x02'
SSTP_ATTRIB_CRYPTO_BINDING = b'\x03'
SSTP_ATTRIB_CRYPTO_BINDING_REQ = b'\x04'

# Status
ATTRIB_STATUS_NO_ERROR = b'\x00\x00\x00\x00'
ATTRIB_STATUS_DUPLICATE_ATTRIBUTE = b'\x00\x00\x00\x01'
ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE = b'\x00\x00\x00\x02'
ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH = b'\x00\x00\x00\x03'
ATTRIB_STATUS_VALUE_NOT_SUPPORTED = b'\x00\x00\x00\x04'
ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED = b'\x00\x00\x00\x05'
ATTRIB_STATUS_RETRY_COUNT_EXCEEDED = b'\x00\x00\x00\x06'
ATTRIB_STATUS_INVALID_FRAME_RECEIVED = b'\x00\x00\x00\x07'
ATTRIB_STATUS_NEGOTIATION_TIMEOUT = b'\x00\x00\x00\x08'
ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG = b'\x00\x00\x00\x09'
ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING = b'\x00\x00\x00\x0a'
ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG = b'\x00\x00\x00\x0b'

