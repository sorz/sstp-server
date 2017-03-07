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

# State
SERVER_CALL_DISCONNECTED = 'Server_Call_Disconnected'
SERVER_CONNECT_REQUEST_PENDING = 'Server_Connect_Request_Pending'
SERVER_CALL_CONNECTED_PENDING = 'Server_Call_Connected_Pending'
SERVER_CALL_CONNECTED = 'Server_Call_Connected'
CALL_DISCONNECT_IN_PROGRESS_1 = 'Call_Disconnect_In_Progress_1'
CALL_DISCONNECT_IN_PROGRESS_2 = 'Call_Disconnect_In_Progress_2'
CALL_DISCONNECT_TIMEOUT_PENDING = 'Call_Disconnect_Timeout_Pending'
CALL_DISCONNECT_ACK_PENDING = 'Call_Disconnect_Timeout_Pending'
CALL_ABORT_IN_PROGRESS_1 = 'Call_Abort_In_Progress_1'
CALL_ABORT_IN_PROGRESS_2 = 'Call_Abort_In_Progress_2'
CALL_ABORT_TIMEOUT_PENDING = 'Call_Abort_Timeout_Pending'
CALL_ABORT_PENDING = 'Call_Abort_Timeout_Pending'

# Message Type
class MsgType:
    __metaclass__ = SimpleEnumMeta
    CALL_CONNECT_REQUEST = '\x00\x01'
    CALL_CONNECT_ACK = '\x00\x02'
    CALL_CONNECT_NAK = '\x00\x03'
    CALL_CONNECTED = '\x00\x04'
    CALL_ABORT = '\x00\x05'
    CALL_DISCONNECT = '\x00\x06'
    CALL_DISCONNECT_ACK = '\x00\x07'
    ECHO_REQUEST = '\x00\x08'
    ECHO_RESPONSE = '\x00\x09'

# Attribute ID
SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID = '\x01'
SSTP_ATTRIB_STATUS_INFO = '\x02'
SSTP_ATTRIB_CRYPTO_BINDING = '\x03'
SSTP_ATTRIB_CRYPTO_BINDING_REQ = '\x04'

# Protocol ID
SSTP_ENCAPSULATED_PROTOCOL_PPP = '\x00\x01'

# Hash Protocol Bitmask
CERT_HASH_PROTOCOL_SHA1 = '\x01'
CERT_HASH_PROTOCOL_SHA256 = '\x02'

# AttribID
SSTP_ATTRIB_NO_ERROR = '\x00'
SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID = '\x01'
SSTP_ATTRIB_STATUS_INFO = '\x02'
SSTP_ATTRIB_CRYPTO_BINDING = '\x03'
SSTP_ATTRIB_CRYPTO_BINDING_REQ = '\x04'

# Status
ATTRIB_STATUS_NO_ERROR = '\x00\x00\x00\x00'
ATTRIB_STATUS_DUPLICATE_ATTRIBUTE = '\x00\x00\x00\x01'
ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE = '\x00\x00\x00\x02'
ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH = '\x00\x00\x00\x03'
ATTRIB_STATUS_VALUE_NOT_SUPPORTED = '\x00\x00\x00\x04'
ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED = '\x00\x00\x00\x05'
ATTRIB_STATUS_RETRY_COUNT_EXCEEDED = '\x00\x00\x00\x06'
ATTRIB_STATUS_INVALID_FRAME_RECEIVED = '\x00\x00\x00\x07'
ATTRIB_STATUS_NEGOTIATION_TIMEOUT = '\x00\x00\x00\x08'
ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG = '\x00\x00\x00\x09'
ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING = '\x00\x00\x00\x0a'
ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG = '\x00\x00\x00\x0b'

