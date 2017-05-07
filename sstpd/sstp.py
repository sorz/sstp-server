import os
import struct
import logging
import asyncio
from enum import Enum
from asyncio import Protocol
from functools import partial
from binascii import hexlify

from . import __version__
from .constants import *
from .packets import SSTPDataPacket, SSTPControlPacket
from .utils import hexdump
from .ppp import PPPDProtocol, PPPDProtocolFactory, is_ppp_control_frame
from .proxy_protocol import parse_pp_header, PPException, PPNoEnoughData


HTTP_REQUEST_BUFFER_SIZE = 10 * 1024
HELLO_TIMEOUT = 60

def parse_length(s):
    return ((s[0] & 0x0f) << 8) + s[1]  # Ignore R


class State(Enum):
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


class SSTPProtocol(Protocol):

    def __init__(self):
        self.loop = asyncio.get_event_loop()
        self.state = State.SERVER_CALL_DISCONNECTED
        self.sstp_packet_len = 0
        self.receive_buf = bytearray()
        self.nonce = None
        self.pppd = None
        self.retry_counter = 0
        self.hello_timer = None
        self.reset_hello_timer()
        self.proxy_protocol_passed = False
        self.remote_host = None


    def connection_made(self, transport):
        self.transport = transport
        self.proxy_protocol_passed = not self.factory.proxy_protocol
        peer = self.transport.get_extra_info("peername")
        if hasattr(peer, 'host'):
            self.remote_host = str(peer.host)


    def data_received(self, data):
        if self.state is State.SERVER_CALL_DISCONNECTED:
            if self.proxy_protocol_passed:
                self.http_data_received(data)
            else:
                self.proxy_protocol_data_received(data)
        else:
            self.sstp_data_received(data)


    def connection_lost(self, reason):
        logging.debug('Connection finished.')
        if self.pppd is not None and self.pppd.transport is not None:
            self.pppd.transport.close()
            if self.factory.remote_pool is not None:
                self.factory.remote_pool.unregister(self.pppd.remote)
        self.hello_timer.cancel()


    def proxy_protocol_data_received(self, data):
        self.receive_buf.extend(data)
        try:
            src, dest, self.receive_buf = parse_pp_header(self.receive_buf)
        except PPNoEnoughData:
            pass
        except PPException as e:
            logging.warning('PROXY PROTOCOL parsing error: %s', str(e))
            self.transport.close()
        else:
            logging.debug('PROXY PROTOCOL header parsed: src %s, dest %s', src, dest)
            self.remote_host = src[0]
            self.proxy_protocol_passed = True
            if self.receive_buf:
                self.data_received(b'')


    def http_data_received(self, data):
        def close(*args):
            logging.warning(*args)
            self.transport.close()

        self.receive_buf.extend(data)
        if b"\r\n\r\n" not in self.receive_buf:
            if len(self.receive_buf) > HTTP_REQUEST_BUFFER_SIZE:
                close('Request too large, may not a valid HTTP request.')
            return
        request_line = self.receive_buf.split(b'\r\n')[0]
        self.receive_buf.clear()
        try:
            method, uri, version = request_line.split()
        except ValueError:
            return close('Not a valid HTTP request.')
        if method != b"SSTP_DUPLEX_POST" or version != b"HTTP/1.1":
            return close('Unexpected HTTP method (%s) and/or version (%s).',
                         method.decode(errors='replace'),
                         version.decode(errors='replace'))
        self.transport.write(b'HTTP/1.1 200 OK\r\n'
                b'Content-Length: 18446744073709551615\r\n'
                b'Server: SSTP-Server/%s\r\n\r\n' % str(__version__).encode())
        self.state = State.SERVER_CONNECT_REQUEST_PENDING


    def sstp_data_received(self, data):
        self.reset_hello_timer()
        self.receive_buf.extend(data)
        while len(self.receive_buf) >= 4:
            # Check version.
            if self.receive_buf[0] != 0x10:
                logging.warn('Unsupported SSTP version.')
                self.transport.close()
                return
            # Get length if necessary.
            if not self.sstp_packet_len:
                self.sstp_packet_len = parse_length(self.receive_buf[2:4])
            if len(self.receive_buf) < self.sstp_packet_len:
                return
            packet = memoryview(self.receive_buf)[:self.sstp_packet_len]
            self.receive_buf = self.receive_buf[self.sstp_packet_len:]
            self.sstp_packet_len = 0
            self.sstp_packet_received(packet)


    def sstp_packet_received(self, packet):
        c = packet[1] & 0x01
        if c is 0:  # Data packet
            self.sstp_data_packet_received(packet[4:])
        else:  # Control packet
            msg_type = packet[4:6].tobytes()
            num_attrs = struct.unpack('!H', packet[6:8])[0]
            attributes = []
            attrs = packet[8:]
            while len(attributes) < num_attrs:
                id = attrs[1]
                length = parse_length(attrs[2:4])
                value = attrs[4:length]
                attrs = attrs[length:]
                attributes.append((id, value))
            self.sstp_control_packet_received(msg_type, attributes)


    def sstp_data_packet_received(self, data):
        if __debug__:
            logging.debug('sstp => pppd (%s bytes).', len(data))
            logging.log(VERBOSE, hexdump(data))
        if self.pppd is None:
            print('pppd is None.')
            return
        self.pppd.write_frame(data)


    def sstp_control_packet_received(self, msg_type, attributes):
        logging.info('SSTP control packet (%s) received.',
                     MsgType.str.get(msg_type, msg_type))
        if msg_type == MsgType.CALL_CONNECT_REQUEST:
            protocolId = attributes[0][1]
            self.sstp_call_connect_request_received(protocolId)
        elif msg_type == MsgType.CALL_CONNECTED:
            attr = attributes[0][1]
            hash_type = attr[3:4]
            nonce = attr[4:36]
            cert_hash = attr[36:68]
            mac_hash = attr[68:72]
            self.sstp_call_connected_received(hash_type, nonce,
                                              cert_hash, mac_hash)
        elif msg_type == MsgType.CALL_ABORT:
            if attributes:
                self.sstp_msg_call_abort(attributes[0][1])
            else:
                self.sstp_msg_call_abort()
        elif msg_type == MsgType.CALL_DISCONNECT:
            if attributes:
                self.sstp_msg_call_disconnect(attributes[0][1])
            else:
                self.sstp_msg_call_disconnect()
        elif msg_type == MsgType.CALL_DISCONNECT_ACK:
            self.sstp_msg_call_disconnect_ack()
        elif msg_type == MsgType.ECHO_REQUEST:
            self.sstp_msg_echo_request()
        elif msg_type == MsgType.ECHO_RESPONSE:
            self.sstp_msg_echo_response()
        else:
            logging.warn('Unknown type of SSTP control packet.')
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)


    def sstp_call_connect_request_received(self, protocolId):
        if self.state in (State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_ABORT_PENDING,
                State.CALL_DISCONNECT_ACK_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        if self.state is not State.SERVER_CONNECT_REQUEST_PENDING:
            logging.warn('Not in the state.')
            self.transport.close()
            return
        if protocolId != SSTP_ENCAPSULATED_PROTOCOL_PPP:
            logging.warn('Unsupported encapsulated protocol.')
            nak = SSTPControlPacket(MsgType.CALL_CONNECT_NAK)
            nak.attributes = [(SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID,
                    ATTRIB_STATUS_VALUE_NOT_SUPPORTED)]
            self.add_retry_counter_or_abort()
            return
        self.nonce = os.urandom(32)
        ack = SSTPControlPacket(MsgType.CALL_CONNECT_ACK)
        # 3 bytes reserved + 1 byte hash bitmap (SHA-1 only) + nonce.
        ack.attributes = [(SSTP_ATTRIB_CRYPTO_BINDING_REQ,
                b'\x00\x00\x00' + b'\x03' + self.nonce)]
        ack.write_to(self.transport.write)

        remote = ''
        if self.factory.remote_pool:
            remote = self.factory.remote_pool.apply()
            if remote is None:
                logging.warn('IP address pool is full. '
                             'Cannot accpet new connection.')
                self.abort()

        address_argument = '%s:%s' % (self.factory.local, remote)
        args = ['notty', 'file', self.factory.pppd_config_file,
                '115200', address_argument]
        if self.remote_host is not None:
            args += ['remotenumber', self.remote_host]

        factory = PPPDProtocolFactory(callback=self, remote=remote)
        coro = self.loop.subprocess_exec(factory, self.factory.pppd, *args)
        task = asyncio.ensure_future(coro)
        task.add_done_callback(self.pppd_started)
        self.state = State.SERVER_CALL_CONNECTED_PENDING

    def pppd_started(self, task):
        err = task.exception()
        if err is not None:
            logging.warning("Fail to start pppd: %s", err)
            self.abort()
            return
        transport, protocol = task.result()
        self.pppd = protocol
        self.pppd.resume_producing()

    def sstp_call_connected_received(self, hash_type, nonce, cert_hash, mac_hash):
        if self.state in (State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_ABORT_PENDING,
                State.CALL_DISCONNECT_ACK_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        if self.state is not State.SERVER_CALL_CONNECTED_PENDING:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)
        # TODO: check cert_hash and mac_hash
        logging.debug("Received cert hash: %s", hexlify(cert_hash).decode())
        logging.debug("Received MAC hash: %s", hexlify(mac_hash).decode())
        logging.debug("Hash type: %s", hash_type)

        if nonce != self.nonce:
            logging.warn('Received wrong nonce.')
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return
        self.nonce = None

        if self.factory.cert_hash is not None \
                and cert_hash not in self.factory.cert_hash:
            logging.warning("Certificate hash mismatch between server's "
                            "and client's. Reject this connection.")
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return

        self.state = State.SERVER_CALL_CONNECTED
        logging.info('Connection established.')


    def sstp_msg_call_abort(self, status=None):
        if self.state in (State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        logging.warn("Call abort.")
        if self.state is State.CALL_ABORT_PENDING:
            self.loop.call_later(1, self.transport.close)
            return
        self.state = State.CALL_ABORT_IN_PROGRESS_2
        msg = SSTPControlPacket(MsgType.CALL_ABORT)
        msg.write_to(self.transport.write)
        self.state = State.CALL_ABORT_PENDING
        self.loop.call_later(1, self.transport.close)


    def sstp_msg_call_disconnect(self, status=None):
        if self.state in (State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_ABORT_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        logging.info('Received call disconnect request.')
        self.state = State.CALL_DISCONNECT_IN_PROGRESS_2
        ack = SSTPControlPacket(MsgType.CALL_DISCONNECT_ACK)
        ack.write_to(self.transport.write)
        self.state = State.CALL_DISCONNECT_TIMEOUT_PENDING
        self.loop.call_later(1, self.transport.close)

    def sstp_msg_call_disconnect_ack(self):
        if self.state is State.CALL_DISCONNECT_ACK_PENDING:
            self.transport.close()
        elif self.state in (State.CALL_ABORT_PENDING,
                State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        else:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)


    def sstp_msg_echo_request(self):
        if self.state is State.SERVER_CALL_CONNECTED:
            response = SSTPControlPacket(MsgType.ECHO_RESPONSE)
            response.write_to(self.transport.write)
        elif self.state in (State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_ABORT_PENDING,
                State.CALL_DISCONNECT_ACK_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        else:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)


    def sstp_msg_echo_response(self):
        if self.state is State.SERVER_CALL_CONNECTED:
            self.reset_hello_timer()
        elif self.state in (State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_ABORT_PENDING,
                State.CALL_DISCONNECT_ACK_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        else:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)

    def hello_timer_expired(self, close):
        if self.state is State.SERVER_CALL_DISCONNECTED:
            self.transport.close()  # TODO: follow HTTP
        elif close:
            logging.warn('Ping time out.')
            self.abort(ATTRIB_STATUS_NEGOTIATION_TIMEOUT)
        else:
            logging.info('Send echo request.')
            echo = SSTPControlPacket(MsgType.ECHO_REQUEST)
            echo.write_to(self.transport.write)
            self.reset_hello_timer(True)

    def reset_hello_timer(self, close=False):
        if self.hello_timer is not None:
            self.hello_timer.cancel()
        self.hello_timer = self.loop.call_later(HELLO_TIMEOUT,
                partial(self.hello_timer_expired, close=close))

    def add_retry_counter_or_abort(self):
        self.retry_counter += 1
        if self.retry_counter > 3:
            self.abort(ATTRIB_STATUS_RETRY_COUNT_EXCEEDED)


    def abort(self, status=None):
        if status is None:
            logging.warn('Abort.')
        else:
            logging.warn('Abort (%s).', status)
        self.state = State.CALL_DISCONNECT_IN_PROGRESS_1
        msg = SSTPControlPacket(MsgType.CALL_ABORT)
        if status is not None:
            msg.attributes = [(SSTP_ATTRIB_STATUS_INFO, status)]
        msg.write_to(self.transport.write)
        self.state = State.CALL_ABORT_PENDING
        self.loop.call_later(3, self.transport.close)

    def write_ppp_frames(self, frames):
        if self.state is State.SERVER_CALL_CONNECTED_PENDING:
            frames = [f for f in frames if is_ppp_control_frame(f)]
        elif self.state is not State.SERVER_CALL_CONNECTED:
            return
        for frame in frames:
            if __debug__:
                logging.debug('pppd => sstp (%d bytes)', len(frame))
                logging.log(VERBOSE, hexdump(frame))
            SSTPDataPacket(frame).write_to(self.transport.write)

    def ppp_stopped(self):
        if (self.state is not State.SERVER_CONNECT_REQUEST_PENDING and
                self.state is not State.SERVER_CALL_CONNECTED_PENDING and
                self.state is not State.SERVER_CALL_CONNECTED):
            self.transport.close()
            return
        self.state = State.CALL_DISCONNECT_IN_PROGRESS_1
        msg = SSTPControlPacket(MsgType.CALL_DISCONNECT)
        msg.attributes = [(SSTP_ATTRIB_NO_ERROR, ATTRIB_STATUS_NO_ERROR)]
        msg.write_to(self.transport.write)
        self.state = State.CALL_DISCONNECT_ACK_PENDING
        self.loop.call_later(3, self.transport.close)


class SSTPProtocolFactory:
    protocol = SSTPProtocol

    def __init__(self, config, remote_pool, cert_hash=None):
        self.pppd = config.pppd
        self.pppd_config_file = config.pppd_config
        self.local = config.local
        self.proxy_protocol = config.proxy_protocol
        self.remote_pool = remote_pool
        self.cert_hash = cert_hash

    def __call__(self):
        proto = self.protocol()
        proto.factory = self
        return proto

