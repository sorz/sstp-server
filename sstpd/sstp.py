import os
import struct
import logging
import asyncio
from enum import Enum
from asyncio import Protocol
from functools import partial
from binascii import hexlify
import subprocess
import tempfile
import hmac
import hashlib

from . import __version__
from .constants import *
from .packets import SSTPDataPacket, SSTPControlPacket
from .utils import hexdump
from .ppp import PPPDProtocol, PPPDProtocolFactory, is_ppp_control_frame, PPPDSSTPPluginFactory
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

    def __init__(self, logging):
        self.logging = logging
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
        self.correlation_id = None
        self.remote_host = None
        # PPP SSTP API
        self.ppp_sstp = None
        # High(er) LAyer Key (HLAK)
        self.hlak = None
        # Client Compound MAC
        self.client_cmac = None

    def init_logging(self):
        self.logging = SSTPLogging(self.logging,
                {'host': self.remote_host, 'id': self.correlation_id })


    def connection_made(self, transport):
        self.transport = transport
        self.proxy_protocol_passed = not self.factory.proxy_protocol
        peer = self.transport.get_extra_info("peername")
        if hasattr(peer, 'host'):
            self.remote_host = str(peer.host)
        elif type(peer) == tuple:
            self.remote_host = peer[0]


    def data_received(self, data):
        if self.state == State.SERVER_CALL_DISCONNECTED:
            if self.proxy_protocol_passed:
                self.http_data_received(data)
            else:
                self.proxy_protocol_data_received(data)
        else:
            self.sstp_data_received(data)


    def connection_lost(self, reason):
        logging.info('Connection finished.')
        if self.pppd is not None and self.pppd.transport is not None:
            try:
                self.pppd.transport.terminate()
            except ProcessLookupError:
                logging.warning('PPP process is gone already')
                pass
            except Exception as e:
                logging.warning('Unexpected exception %s', str(e))
                pass
            if self.factory.remote_pool is not None:
                self.factory.remote_pool.unregister(self.pppd.remote)
                logging.info('Unregistered address %s', self.pppd.remote);
        self.hello_timer.cancel()
        self.ppp_sstp_api_close()


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
        headers = self.receive_buf.split(b'\r\n')
        request_line = headers[0]
        self.receive_buf.clear()
        try:
            method, uri, version = request_line.split()
        except ValueError:
            return close('Not a valid HTTP request.')
        if method != b"SSTP_DUPLEX_POST" or version != b"HTTP/1.1":
            return close('Unexpected HTTP method (%s) and/or version (%s).',
                         method.decode(errors='replace'),
                         version.decode(errors='replace'))
        for header in filter(lambda x: b'sstpcorrelationid:' in x.lower(), headers):
            try:
                guid = header.decode('ascii').split(':')[1]
                self.correlation_id = guid.strip().strip("{}")
            except:
                pass
        for header in filter(lambda x: b'x-forwarded-for' in x.lower(), headers):
            try:
                hosts = header.decode('ascii').split(':')[1]
                host = hosts.split(',')[0]
                if self.factory.use_http_proxy:
                    self.remote_host = host.strip()
            except:
                pass
        self.init_logging()
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
        if c == 0:  # Data packet
            self.sstp_data_packet_received(packet[4:])
        else:  # Control packet
            msg_type = packet[4:6].tobytes()
            num_attrs = struct.unpack('!H', packet[6:8])[0]
            attributes = []
            attrs = packet[8:]
            while len(attributes) < num_attrs:
                id = attrs[1:2]
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
            attr_obj = next(
                (a for a in attributes if a[0] == SSTP_ATTRIB_CRYPTO_BINDING),
                None
            )
            if attr_obj is None:
                logging.warn('Crypto Binding Attribute '
                        'expected in Call Connect')
                self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
                return
            attr = attr_obj[1]
            if len(attr) != 0x64:
                # MS-SSTP : 2.2.7 Crypto Binding Attribute
                logging.warn('Crypto Binding Attribute length '
                        'MUST be 104 (0x068)')
                self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
                return
            hash_type = attr[3]
            nonce = attr[4:36]
            if hash_type == CERT_HASH_PROTOCOL_SHA1:
                # strip and ignore padding
                cert_hash = attr[36:56]
                mac_hash = attr[68:88]
            elif hash_type == CERT_HASH_PROTOCOL_SHA256:
                cert_hash = attr[36:68]
                mac_hash = attr[68:100]
            else:
                logging.warn('Unsupported hash protocol in Crypto '
                    'Binding Attribute.')
                self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
                return
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
        if self.state != State.SERVER_CONNECT_REQUEST_PENDING:
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
        # hash protocol bitmask
        hpb = 0
        if len(self.factory.cert_hash.sha1) > 0:
            hpb |= CERT_HASH_PROTOCOL_SHA1
        if len(self.factory.cert_hash.sha256) > 0:
            hpb |= CERT_HASH_PROTOCOL_SHA256
        # 3 bytes reserved + 1 byte hash bitmap + nonce.
        ack.attributes = [(SSTP_ATTRIB_CRYPTO_BINDING_REQ,
                b'\x00\x00\x00' + bytes([hpb]) + self.nonce)]
        ack.write_to(self.transport.write)

        remote = ''
        if self.factory.remote_pool:
            remote = self.factory.remote_pool.apply()
            if remote is None:
                logging.warn('IP address pool is full. '
                             'Cannot accept new connection.')
                self.abort()
                return
            logging.info('Registered address %s', remote);

        address_argument = '%s:%s' % (self.factory.local, remote)
        args = ['notty', 'file', self.factory.pppd_config_file,
                '115200', address_argument]
        if self.factory.pppd_sstp_api_plugin is not None:
            # create a unique socket filename
            ppp_sock = tempfile.NamedTemporaryFile(
                    prefix='ppp-sstp-api-', suffix='.sock')
            args += ['plugin', self.factory.pppd_sstp_api_plugin,
                    'sstp-sock', ppp_sock.name]
            ppp_event = self.loop.create_unix_server(
                    PPPDSSTPPluginFactory(callback=self),
                    path=ppp_sock.name)
            ppp_sock.close()
            task = asyncio.create_task(ppp_event)
            task.add_done_callback(self.ppp_sstp_api)

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

    def ppp_sstp_api(self, task):
        err = task.exception()
        if err is not None:
            logging.warning("Fail to start PPP SSTP API: %s", err)
            self.abort()
            return
        server = task.result()
        self.ppp_sstp = server

    def ppp_sstp_api_close(self):
        if self.ppp_sstp is not None:
            socks = list(map(lambda s: s.getsockname(), self.ppp_sstp.sockets))

            logging.debug("Close PPP SSTP API.")
            self.ppp_sstp.close()

            for sock in socks:
                try:
                    logging.debug("Remove SSTP API sock %s", sock)
                    os.remove(sock)
                except:
                    pass

            self.ppp_sstp = None

    def sstp_call_connected_received(self, hash_type, nonce, cert_hash, mac_hash):
        if self.state in (State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_ABORT_PENDING,
                State.CALL_DISCONNECT_ACK_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        if self.state != State.SERVER_CALL_CONNECTED_PENDING:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)
            return

        logging.debug("Received certificate %s hash: %s",
                ("SHA1", "SHA256")[hash_type == CERT_HASH_PROTOCOL_SHA256],
                hexlify(cert_hash).decode())
        logging.debug("Received MAC hash: %s", hexlify(mac_hash).decode())

        if nonce != self.nonce:
            logging.error('Received wrong nonce.')
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return

        if self.factory.cert_hash is not None \
                and cert_hash not in self.factory.cert_hash:
            logging.error("Certificate hash mismatch between server's "
                            "and client's. Reject this connection.")
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return

        if not self.should_verify_crypto_binding():
            logging.debug("No crypto binding needed.")
            self.state = State.SERVER_CALL_CONNECTED
            logging.info('Connection established.')
            return

        if self.hlak is None:
            logging.warning("Waiting for the Higher Layer Authentication "
                    "Key (HLAK) to verify Crypto Binding.")
            self.client_cmac = mac_hash
            return

        self.sstp_call_connected_crypto_binding(mac_hash)


    def sstp_call_connected_crypto_binding(self, mac_hash):
        if self.hlak is None:
            logging.error("Failed to verify Crypto Binding, as the "
                    "Higher Layer Authentication Key is missing.")
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return

        hash_type = (CERT_HASH_PROTOCOL_SHA1,
                CERT_HASH_PROTOCOL_SHA256)[len(mac_hash) == 32]

        # Compound MAC Key (CMK) seed
        cmk_seed = b'SSTP inner method derived CMK'
        cmk_digest = (hashlib.sha1, hashlib.sha256)\
                [hash_type == CERT_HASH_PROTOCOL_SHA256]

        # T1 = HMAC(HLAK, S | LEN | 0x01)
        t1 = hmac.new(self.hlak, digestmod=cmk_digest)

        # CMK len (length of digest) - 16-bits little endian
        cmk_len = bytes((t1.digest_size, 0))

        t1.update(cmk_seed)
        t1.update(cmk_len)
        t1.update(b'\x01')

        cmk = t1.digest()
        if __debug__:
            logging.debug("Crypto Binding CMK %s", t1.hexdigest())

        # reconstruct Call Connect message with zeroed CMAC field
        cc_msg = bytes((0x10, 0x01, 0x00, 0x70))
        cc_msg += MsgType.CALL_CONNECTED
        # number of attributes + reserved
        cc_msg += bytes((0x00, 0x01, 0x00))
        cc_msg += SSTP_ATTRIB_CRYPTO_BINDING
        # attr length + reserved
        cc_msg += bytes((0x00, 0x68, 0x00, 0x00, 0x00))
        cc_msg += bytes([hash_type])
        cc_msg += self.nonce
        cc_msg += self.factory.cert_hash[hash_type == CERT_HASH_PROTOCOL_SHA256]
        # [padding + ] zeroed cmac [+ padding]
        cc_msg += bytes(0x70 - len(cc_msg))

        # CMAC = HMAC(CMK, CC_MSG)
        cmac = hmac.new(cmk, digestmod=cmk_digest)
        cmac.update(cc_msg)

        if __debug__:
            logging.debug("Crypto Binding CMAC %s", cmac.hexdigest())

        if not hmac.compare_digest(cmac.digest(), mac_hash):
            logging.error("Crypto Binding is invalid.")
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return

        logging.info("Crypto Binding is valid.")
        self.state = State.SERVER_CALL_CONNECTED
        logging.info('Connection established.')


    def sstp_msg_call_abort(self, status=None):
        if self.state in (State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        logging.warn("Call abort.")
        if self.state == State.CALL_ABORT_PENDING:
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
        if self.state == State.CALL_DISCONNECT_ACK_PENDING:
            self.transport.close()
        elif self.state in (State.CALL_ABORT_PENDING,
                State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        else:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)


    def sstp_msg_echo_request(self):
        if self.state == State.SERVER_CALL_CONNECTED:
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
        if self.state == State.SERVER_CALL_CONNECTED:
            self.reset_hello_timer()
        elif self.state in (State.CALL_ABORT_TIMEOUT_PENDING,
                State.CALL_ABORT_PENDING,
                State.CALL_DISCONNECT_ACK_PENDING,
                State.CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        else:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)

    def hello_timer_expired(self, close):
        if self.state == State.SERVER_CALL_DISCONNECTED:
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
        if self.state == State.SERVER_CALL_CONNECTED_PENDING:
            frames = [f for f in frames if is_ppp_control_frame(f)]
        elif self.state != State.SERVER_CALL_CONNECTED:
            return
        for frame in frames:
            if __debug__:
                logging.debug('pppd => sstp (%d bytes)', len(frame))
                logging.log(VERBOSE, hexdump(frame))
            SSTPDataPacket(frame).write_to(self.transport.write)

    def ppp_stopped(self):
        if (self.state != State.SERVER_CONNECT_REQUEST_PENDING and
                self.state != State.SERVER_CALL_CONNECTED_PENDING and
                self.state != State.SERVER_CALL_CONNECTED):
            self.transport.close()
            return
        self.state = State.CALL_DISCONNECT_IN_PROGRESS_1
        msg = SSTPControlPacket(MsgType.CALL_DISCONNECT)
        msg.attributes = [(SSTP_ATTRIB_NO_ERROR, ATTRIB_STATUS_NO_ERROR)]
        msg.write_to(self.transport.write)
        self.state = State.CALL_DISCONNECT_ACK_PENDING
        self.loop.call_later(3, self.transport.close)

    def higher_layer_authentication_key(self, send_key, recv_key):
        # [MS-SSTP] 3.2.5.2 - crypto binding - server mode
        hlak = recv_key + send_key
        # ensure hlak is 32 bytes long
        if len(hlak) < 32:
            hlak += bytes(32 - len(hlak))
        self.hlak = hlak[0:32]

        logging.info("Received Higher Layer Authentication Key.")
        logging.debug("Configured HLAK as %s", self.hlak.hex())

        self.ppp_sstp_api_close()

        if self.client_cmac is not None:
            self.sstp_call_connected_crypto_binding(self.client_cmac)

    def should_verify_crypto_binding(self):
        return (self.factory.pppd_sstp_api_plugin is not None)

class SSTPProtocolFactory:
    protocol = SSTPProtocol

    def __init__(self, config, remote_pool, cert_hash=None):
        self.pppd = config.pppd
        self.pppd_config_file = config.pppd_config
        # detect ppp_sstp_api_plugin
        ppp_sstp_api_plugin = 'sstp-pppd-plugin.so'
        has_plugin = subprocess.run(
                [self.pppd, 'plugin', ppp_sstp_api_plugin, 'notty', 'dryrun'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.pppd_sstp_api_plugin = (None, ppp_sstp_api_plugin)\
                [has_plugin.returncode == 0]
        self.local = config.local
        self.proxy_protocol = config.proxy_protocol
        self.use_http_proxy = (config.no_ssl and not config.proxy_protocol)
        self.remote_pool = remote_pool
        self.cert_hash = cert_hash
        self.logging = logging.getLogger('SSTP')

    def __call__(self):
        proto = self.protocol(self.logging)
        proto.factory = self
        return proto

class SSTPLogging(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        return '[%s/%s] %s' % (self.extra['id'], self.extra['host'], msg), kwargs

