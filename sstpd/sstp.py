import asyncio
import hmac
import logging
import os
import pty
import struct
import tty
from asyncio import Protocol, SubprocessTransport, Task, Transport
from binascii import hexlify
from collections.abc import MutableMapping
from enum import Enum
from functools import partial
from typing import Any

from . import __version__
from .address import IPPool
from .certtool import Fingerprint
from .codec import PppDecoder
from .constants import (
    ATTRIB_STATUS_INVALID_FRAME_RECEIVED,
    ATTRIB_STATUS_NEGOTIATION_TIMEOUT,
    ATTRIB_STATUS_NO_ERROR,
    ATTRIB_STATUS_RETRY_COUNT_EXCEEDED,
    ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED,
    ATTRIB_STATUS_VALUE_NOT_SUPPORTED,
    SSTP_ATTRIB_CRYPTO_BINDING,
    SSTP_ATTRIB_CRYPTO_BINDING_REQ,
    SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID,
    SSTP_ATTRIB_NO_ERROR,
    SSTP_ATTRIB_STATUS_INFO,
    SSTP_ENCAPSULATED_PROTOCOL_PPP,
    VERBOSE,
    HashProtocol,
    MsgType,
)
from .packets import SSTPControlPacket
from .ppp import PPPCallback, PPPDProtocol, PPPDProtocolFactory, is_ppp_control_frame
from .proxy_protocol import PPException, PPNoEnoughData, parse_pp_header
from .utils import hexdump

HTTP_REQUEST_BUFFER_SIZE = 10 * 1024
HELLO_TIMEOUT = 60

logger = logging.getLogger("SSTP")


def parse_length(s: bytes | memoryview | bytearray) -> int:
    return ((s[0] & 0x0F) << 8) + s[1]  # Ignore R


class State(Enum):
    SERVER_CALL_DISCONNECTED = "Server_Call_Disconnected"
    SERVER_CONNECT_REQUEST_PENDING = "Server_Connect_Request_Pending"
    SERVER_CALL_CONNECTED_PENDING = "Server_Call_Connected_Pending"
    SERVER_CALL_CONNECTED = "Server_Call_Connected"
    CALL_DISCONNECT_IN_PROGRESS_1 = "Call_Disconnect_In_Progress_1"
    CALL_DISCONNECT_IN_PROGRESS_2 = "Call_Disconnect_In_Progress_2"
    CALL_DISCONNECT_TIMEOUT_PENDING = "Call_Disconnect_Timeout_Pending"
    CALL_DISCONNECT_ACK_PENDING = "Call_Disconnect_Timeout_Pending"
    CALL_ABORT_IN_PROGRESS_1 = "Call_Abort_In_Progress_1"
    CALL_ABORT_IN_PROGRESS_2 = "Call_Abort_In_Progress_2"
    CALL_ABORT_TIMEOUT_PENDING = "Call_Abort_Timeout_Pending"
    CALL_ABORT_PENDING = "Call_Abort_Timeout_Pending"


class SSTPProtocol(Protocol):
    def __init__(self, factory: "SSTPProtocolFactory") -> None:
        self.factory = factory
        self.logger = logger
        self.loop = asyncio.get_event_loop()
        self.state = State.SERVER_CALL_DISCONNECTED
        self.receive_buf = bytearray()
        self.nonce: bytes | None = None
        self.pppd: PPPDProtocol | None = None
        self.ppp_decoder = PppDecoder()
        self.retry_counter = 0
        self.hello_timer: asyncio.TimerHandle | None = None
        self.reset_hello_timer()
        self.proxy_protocol_passed = not self.factory.proxy_protocol
        self.correlation_id: str | None = None
        self.remote_host: str | None = None
        self.remote_port: int | None = None
        self.transport: Transport | None = None

    def update_logger(self) -> None:
        self.logger = SessionLogger(
            self.logger,
            self.correlation_id or "?",
            self.remote_host,
            self.remote_port,
        )

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, Transport)
        self.transport = transport
        peer = transport.get_extra_info("peername")
        transport.set_write_buffer_limits(512 * 1024, 128 * 1024)
        if hasattr(peer, "host"):
            self.remote_host = str(peer.host)
            self.remote_port = int(peer.port) if hasattr(peer, "port") else None
        elif isinstance(peer, tuple):
            self.remote_host = peer[0]
            self.remote_port = peer[1]

    def data_received(self, data: bytes) -> None:
        if self.state == State.SERVER_CALL_DISCONNECTED:
            if self.proxy_protocol_passed:
                self.http_data_received(data)
            else:
                self.proxy_protocol_data_received(data)
        else:
            self.sstp_data_received(data)

    def connection_lost(self, exc: Exception | None) -> None:
        self.logger.info("Connection finished.")
        if self.pppd is not None and self.pppd.transport is not None:
            try:
                self.pppd.transport.terminate()
            except ProcessLookupError:
                self.logger.warning("PPP process is gone already")
                pass
            except Exception as e:
                self.logger.warning("Unexpected exception %s", str(e))
                pass
            if self.factory.remote_pool is not None and self.pppd.remote is not None:
                self.factory.remote_pool.unregister(self.pppd.remote)
                self.logger.info("Unregistered address %s", self.pppd.remote)
        if self.hello_timer:
            self.hello_timer.cancel()

    def proxy_protocol_data_received(self, data: bytes) -> None:
        self.receive_buf.extend(data)
        try:
            res = parse_pp_header(self.receive_buf)
            src = res.src
            dest = res.dest
            self.receive_buf = res.remaining_data
        except PPNoEnoughData:
            pass
        except PPException as e:
            self.logger.warning("PROXY PROTOCOL parsing error: %s", str(e))
            if self.transport:
                self.transport.close()
        else:
            self.logger.debug(
                "PROXY PROTOCOL header parsed: src %s, dest %s", src, dest
            )
            if src:
                self.remote_host = src.ip
            self.proxy_protocol_passed = True
            if self.receive_buf:
                self.data_received(b"")

    def http_data_received(self, data: bytes) -> None:
        def close(*args: Any) -> None:
            logging.warning(*args)
            if self.transport:
                self.transport.close()

        self.receive_buf.extend(data)
        if b"\r\n\r\n" not in self.receive_buf:
            if len(self.receive_buf) > HTTP_REQUEST_BUFFER_SIZE:
                close("Request too large, may not a valid HTTP request.")
            return
        headers = self.receive_buf.split(b"\r\n")
        request_line = headers[0]
        self.receive_buf.clear()
        try:
            method, uri, version = request_line.split()
        except ValueError:
            return close("Not a valid HTTP request.")
        if method != b"SSTP_DUPLEX_POST" or version != b"HTTP/1.1":
            return close(
                "Unexpected HTTP method (%s) and/or version (%s).",
                method.decode(errors="replace"),
                version.decode(errors="replace"),
            )
        for header in filter(lambda x: b"sstpcorrelationid:" in x.lower(), headers):
            try:
                guid = header.decode("ascii").split(":")[1]
                self.correlation_id = guid.strip().strip("{}")
            except Exception:
                pass
        host, port = None, None
        for header in filter(lambda x: b"x-forwarded-for" in x.lower(), headers):
            try:
                hosts = header.decode("ascii").split(":")[1]
                host = hosts.split(",")[0].strip()
            except Exception:
                pass
        for header in filter(lambda x: b"x-forwarded-sourceport" in x.lower(), headers):
            try:
                ports = header.decode("ascii").split(":")[1]
                port = int(ports.split(",")[0].strip())
            except Exception:
                pass
        if self.factory.use_http_proxy and host is not None:
            self.remote_host = host
            # port can be None if not forwarded
            self.remote_port = port
        self.update_logger()
        if self.transport:
            self.transport.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 18446744073709551615\r\n"
                b"Server: SSTP-Server/%s\r\n\r\n" % str(__version__).encode()
            )
        self.state = State.SERVER_CONNECT_REQUEST_PENDING

    def sstp_data_received(self, data: bytes) -> None:
        self.reset_hello_timer()
        if self.receive_buf:
            self.receive_buf.extend(data)
            buf = memoryview(self.receive_buf).toreadonly()
        else:
            buf = memoryview(data).toreadonly()

        data_pkts = []
        while len(buf) >= 4:
            # parse header
            ver = buf[0]
            is_ctrl_pkt = buf[1] & 0x01 == 1
            pkt_len = parse_length(buf[2:4])

            # check version & length
            if ver != 0x10:
                self.logger.warning("Unsupported SSTP version.")
                if self.transport:
                    self.transport.close()
                return
            if len(buf) < pkt_len:
                break

            pkt, buf = buf[:pkt_len], buf[pkt_len:]
            if is_ctrl_pkt:
                self.sstp_control_packet_received(pkt)
            else:  # data packets: process in batch
                data_pkts.append(pkt[4:])

        self.receive_buf = bytearray(buf)
        self.sstp_data_packets_received(data_pkts)

    def sstp_data_packets_received(self, pkts: list[memoryview]) -> None:
        if self.pppd is None:
            print("pppd is None.")
            return
        if self.state == State.SERVER_CALL_CONNECTED_PENDING:
            # only ppp control frames are allowed
            pkts = [p for p in pkts if is_ppp_control_frame(p)]

        if self.state in (
            State.SERVER_CALL_CONNECTED,
            State.SERVER_CALL_CONNECTED_PENDING,
        ):
            if self.factory.log_level <= logging.DEBUG:
                self.logger.debug("sstp => pppd (%s packets)", len(pkts))
                for pkt in pkts:
                    self.logger.log(VERBOSE, "sstp => pppd (%s bytes)", len(pkt))
                    self.logger.log(VERBOSE, hexdump(pkt))
            # LCP may not been done before SERVER_CALL_CONNECTED
            # assume asyncmap = 0 after fully connected
            full_escape = self.state != State.SERVER_CALL_CONNECTED
            self.pppd.write_frames(pkts, full_escape)
        else:
            self.logger.info("drop ppp frame from client")

    def sstp_control_packet_received(self, packet: memoryview) -> None:
        # decode message type
        try:
            type = MsgType(packet[4:6].tobytes())
        except ValueError:
            self.logger.warning("Unknown type of SSTP control packet.")
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return
        self.logger.info("SSTP control packet (%s) received.", type.name)

        # decode attributes
        num_attrs = struct.unpack("!H", packet[6:8])[0]
        attributes = []
        attrs = packet[8:]
        while len(attributes) < num_attrs:
            id = attrs[1:2].tobytes()
            length = parse_length(attrs[2:4])
            value = attrs[4:length].tobytes()
            attrs = attrs[length:]
            attributes.append((id, value))

        match type:
            case MsgType.CALL_CONNECT_REQUEST:
                protocolId = attributes[0][1]
                self.sstp_call_connect_request_received(protocolId)
            case MsgType.CALL_CONNECTED:
                attr = attributes[0][1]
                attr_obj = next(
                    (a for a in attributes if a[0] == SSTP_ATTRIB_CRYPTO_BINDING), None
                )
                if attr_obj is None:
                    self.logger.warning(
                        "Crypto Binding Attribute expected in Call Connect"
                    )
                    self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
                    return
                attr = attr_obj[1]
                if len(attr) != 0x64:
                    # MS-SSTP : 2.2.7 Crypto Binding Attribute
                    self.logger.warning(
                        "Crypto Binding Attribute length MUST be 104 (0x068)"
                    )
                    self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
                    return
                hash_type_id = attr[3]
                nonce = attr[4:36]
                try:
                    hash_type = HashProtocol(hash_type_id)
                    match hash_type:
                        case HashProtocol.SHA1:
                            # strip and ignore padding
                            cert_hash = attr[36:56]
                            mac_hash = attr[68:88]
                        case HashProtocol.SHA256:
                            cert_hash = attr[36:68]
                            mac_hash = attr[68:100]
                except ValueError:
                    self.logger.warning(
                        "abort: unsupported hash protocol: %s", hash_type_id
                    )
                    self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
                    return
                self.sstp_call_connected_received(
                    packet, hash_type, nonce, cert_hash, mac_hash
                )
            case MsgType.CALL_ABORT:
                if attributes:
                    self.sstp_msg_call_abort(attributes[0][1])
                else:
                    self.sstp_msg_call_abort()
            case MsgType.CALL_DISCONNECT:
                if attributes:
                    self.sstp_msg_call_disconnect(attributes[0][1])
                else:
                    self.sstp_msg_call_disconnect()
            case MsgType.CALL_DISCONNECT_ACK:
                self.sstp_msg_call_disconnect_ack()
            case MsgType.ECHO_REQUEST:
                self.sstp_msg_echo_request()
            case MsgType.ECHO_RESPONSE:
                self.sstp_msg_echo_response()

    def sstp_call_connect_request_received(self, protocolId: bytes) -> None:
        if self.state in (
            State.CALL_ABORT_TIMEOUT_PENDING,
            State.CALL_ABORT_PENDING,
            State.CALL_DISCONNECT_ACK_PENDING,
            State.CALL_DISCONNECT_TIMEOUT_PENDING,
        ):
            return
        if self.state != State.SERVER_CONNECT_REQUEST_PENDING:
            self.logger.warning("Not in the state.")
            if self.transport:
                self.transport.close()
            return
        if protocolId != SSTP_ENCAPSULATED_PROTOCOL_PPP:
            self.logger.warning("Unsupported encapsulated protocol.")
            nak = SSTPControlPacket(MsgType.CALL_CONNECT_NAK)
            nak.attributes = [
                (
                    SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID,
                    ATTRIB_STATUS_VALUE_NOT_SUPPORTED,
                )
            ]
            self.add_retry_counter_or_abort()
            return
        self.nonce = os.urandom(32)
        ack = SSTPControlPacket(MsgType.CALL_CONNECT_ACK)
        # hash protocol bitmask
        hpb = 0
        if self.factory.cert_hash and len(self.factory.cert_hash.sha1) > 0:
            hpb |= HashProtocol.SHA1.value
        if self.factory.cert_hash and len(self.factory.cert_hash.sha256) > 0:
            hpb |= HashProtocol.SHA256.value
        # 3 bytes reserved + 1 byte hash bitmap + nonce.
        ack.attributes = [
            (
                SSTP_ATTRIB_CRYPTO_BINDING_REQ,
                b"\x00\x00\x00" + bytes([hpb]) + self.nonce,
            )
        ]
        if self.transport:
            ack.write_to(self.transport.write)

        remote = ""
        if self.factory.remote_pool:
            remote_ip = self.factory.remote_pool.apply()
            if remote_ip is None:
                self.logger.warning(
                    "IP address pool is full. Cannot accept new connection."
                )
                self.abort()
                return
            remote = str(remote_ip)
            self.logger.info("Registered address %s", remote)

        master_fd, slave_fd = pty.openpty()
        tty.setraw(slave_fd)
        args = [
            os.ttyname(slave_fd),
            "file",
            self.factory.pppd_config_file,
            "%s:%s" % (self.factory.local, remote),
            "nodetach",
        ]
        # TODO: add plugin to args

        if self.remote_host is not None:
            args += ["remotenumber", self.remote_host]

        ppp_env = os.environ.copy()
        if self.correlation_id is not None:
            ppp_env["SSTP_REMOTE_ID"] = self.correlation_id
        if self.remote_host is not None:
            ppp_env["SSTP_REMOTE_HOST"] = self.remote_host
        if self.remote_port is not None:
            ppp_env["SSTP_REMOTE_PORT"] = str(self.remote_port)

        factory = PPPDProtocolFactory(
            remote=remote,
            master_fd=master_fd,
            slave_fd=slave_fd,
            callback=PPPCallback(
                pause_producing=self.pause_producing,
                resume_producing=self.resume_producing,
                data_received=self.ppp_data_received,
                exited=self.ppp_exited,
            ),
        )
        coro = self.loop.subprocess_exec(factory, self.factory.pppd, *args, env=ppp_env)
        task = asyncio.ensure_future(coro)
        task.add_done_callback(self.pppd_started)
        self.state = State.SERVER_CALL_CONNECTED_PENDING

    def pppd_started(
        self, task: Task[tuple[SubprocessTransport, PPPDProtocol]]
    ) -> None:
        err = task.exception()
        if err is not None:
            self.logger.warning("Fail to start pppd: %s", err)
            self.abort()
            return
        transport, protocol = task.result()
        self.pppd = protocol
        protocol.resume_producing()

    def sstp_call_connected_received(
        self,
        packet: memoryview,
        hash_type: HashProtocol,
        nonce: bytes,
        cert_hash: bytes,
        mac_hash: bytes,
    ) -> None:
        if self.state in (
            State.CALL_ABORT_TIMEOUT_PENDING,
            State.CALL_ABORT_PENDING,
            State.CALL_DISCONNECT_ACK_PENDING,
            State.CALL_DISCONNECT_TIMEOUT_PENDING,
        ):
            return
        if self.state != State.SERVER_CALL_CONNECTED_PENDING:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)
            return

        # 1) Check nonce
        if nonce != self.nonce:
            self.logger.warning("abort: wrong nonce received")
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return

        # 2) Check certificate hash
        self.logger.debug(
            "Received cert hash %s: %s",
            hash_type,
            hexlify(cert_hash).decode(),
        )
        if (
            self.factory.cert_hash is not None
            and cert_hash not in self.factory.cert_hash
        ):
            self.logger.warning("abort: certificate hash mismatched")
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return

        # 3) Check crypto binding
        self.logger.debug("Received CMAC: %s", hexlify(mac_hash).decode())
        assert self.pppd is not None
        if self.pppd.plugin.loaded:
            cmk = self.pppd.plugin.cmk.get(hash_type.name)
            if cmk is None:
                self.logger.warning("abort: cmk not received from pppd")
                self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
                return
            # CMAC: HMAC(key=CMK, data=packet*)
            # *cmac & padding zeroed out
            cmac = hmac.new(cmk, digestmod=hash_type.hasher)
            cmac.update(packet[:16])  # all headers
            cmac.update(nonce)
            cmac.update(cert_hash)
            cmac.update(bytes(32 - len(cert_hash)))  # padding
            cmac.update(bytes(32))  # cmac

            self.logger.debug("CMAC: %s", cmac.hexdigest())

            if not hmac.compare_digest(cmac.digest(), mac_hash):
                self.logger.error("Crypto Binding is invalid.")
                self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
                return
        else:
            self.logger.warning("pppd plugin not loaded, crypto binding was skipped")

        self.state = State.SERVER_CALL_CONNECTED
        self.logger.info("Connection established.")

    def sstp_msg_call_abort(self, status: bytes | None = None) -> None:
        if self.state in (
            State.CALL_ABORT_TIMEOUT_PENDING,
            State.CALL_DISCONNECT_TIMEOUT_PENDING,
        ):
            return
        self.logger.warning("Call abort.")
        if self.state == State.CALL_ABORT_PENDING:
            self.loop.call_later(1, self.close_transport)
            return
        self.state = State.CALL_ABORT_IN_PROGRESS_2
        msg = SSTPControlPacket(MsgType.CALL_ABORT)
        if self.transport:
            msg.write_to(self.transport.write)
        self.state = State.CALL_ABORT_PENDING
        self.loop.call_later(1, self.close_transport)

    def sstp_msg_call_disconnect(self, status: bytes | None = None) -> None:
        if self.state in (
            State.CALL_ABORT_TIMEOUT_PENDING,
            State.CALL_ABORT_PENDING,
            State.CALL_DISCONNECT_TIMEOUT_PENDING,
        ):
            return
        self.logger.info("Received call disconnect request.")
        self.state = State.CALL_DISCONNECT_IN_PROGRESS_2
        ack = SSTPControlPacket(MsgType.CALL_DISCONNECT_ACK)
        if self.transport:
            ack.write_to(self.transport.write)
        self.state = State.CALL_DISCONNECT_TIMEOUT_PENDING
        self.loop.call_later(1, self.close_transport)

    def sstp_msg_call_disconnect_ack(self) -> None:
        if self.state == State.CALL_DISCONNECT_ACK_PENDING:
            if self.transport:
                self.transport.close()
        elif self.state in (
            State.CALL_ABORT_PENDING,
            State.CALL_ABORT_TIMEOUT_PENDING,
            State.CALL_DISCONNECT_TIMEOUT_PENDING,
        ):
            return
        else:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)

    def sstp_msg_echo_request(self) -> None:
        if self.state == State.SERVER_CALL_CONNECTED:
            response = SSTPControlPacket(MsgType.ECHO_RESPONSE)
            if self.transport:
                response.write_to(self.transport.write)
        elif self.state in (
            State.CALL_ABORT_TIMEOUT_PENDING,
            State.CALL_ABORT_PENDING,
            State.CALL_DISCONNECT_ACK_PENDING,
            State.CALL_DISCONNECT_TIMEOUT_PENDING,
        ):
            return
        else:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)

    def sstp_msg_echo_response(self) -> None:
        if self.state == State.SERVER_CALL_CONNECTED:
            self.reset_hello_timer()
        elif self.state in (
            State.CALL_ABORT_TIMEOUT_PENDING,
            State.CALL_ABORT_PENDING,
            State.CALL_DISCONNECT_ACK_PENDING,
            State.CALL_DISCONNECT_TIMEOUT_PENDING,
        ):
            return
        else:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)

    def hello_timer_expired(self, close: bool) -> None:
        if self.state == State.SERVER_CALL_DISCONNECTED:
            if self.transport:
                self.transport.close()  # TODO: follow HTTP
        elif close:
            self.logger.warning("Ping time out.")
            self.abort(ATTRIB_STATUS_NEGOTIATION_TIMEOUT)
        else:
            self.logger.info("Send echo request.")
            echo = SSTPControlPacket(MsgType.ECHO_REQUEST)
            if self.transport:
                echo.write_to(self.transport.write)
            self.reset_hello_timer(True)

    def reset_hello_timer(self, close: bool = False) -> None:
        if self.hello_timer is not None:
            if self.hello_timer.when() - self.loop.time() < HELLO_TIMEOUT * 0.9:
                self.hello_timer.cancel()
                self.hello_timer = None
        if self.hello_timer is None:
            self.hello_timer = self.loop.call_later(
                HELLO_TIMEOUT, partial(self.hello_timer_expired, close=close)
            )

    def add_retry_counter_or_abort(self) -> None:
        self.retry_counter += 1
        if self.retry_counter > 3:
            self.abort(ATTRIB_STATUS_RETRY_COUNT_EXCEEDED)

    def abort(self, status: bytes | None = None) -> None:
        if status is None:
            self.logger.warning("Abort.")
        else:
            self.logger.warning("Abort (%s).", status)
        self.state = State.CALL_DISCONNECT_IN_PROGRESS_1
        msg = SSTPControlPacket(MsgType.CALL_ABORT)
        if status is not None:
            msg.attributes = [(SSTP_ATTRIB_STATUS_INFO, status)]
        if self.transport:
            msg.write_to(self.transport.write)
        self.state = State.CALL_ABORT_PENDING
        self.loop.call_later(3, self.close_transport)

    def close_transport(self) -> None:
        if self.transport:
            self.transport.close()

    def pause_writing(self) -> None:
        print("SSTP pause_writing")
        if self.pppd is not None:
            self.pppd.pause_producing()

    def resume_writing(self) -> None:
        print("SSTP resume_writing")
        if self.pppd is not None:
            self.pppd.resume_producing()

    def pause_producing(self) -> None:
        self.logger.debug("Pause sstp producting")
        if self.transport is not None:
            self.transport.pause_reading()

    def resume_producing(self) -> None:
        self.logger.debug("Resume sstp producing")
        if self.transport is not None:
            self.transport.resume_reading()

    def ppp_data_received(self, data: bytes) -> None:
        match self.state:
            case State.SERVER_CALL_CONNECTED:
                ctrl_only = False
            case State.SERVER_CALL_CONNECTED_PENDING:
                ctrl_only = True
            case state:
                self.logger.debug("drop %d bytes ppp data under %s", len(data), state)
                return
        sstp = self.ppp_decoder.ppp_to_sstp(data, ctrl_only)
        if self.factory.log_level <= logging.DEBUG:
            self.logger.debug("ppp => sstp (%d => %d)", len(data), len(sstp))
            self.logger.log(VERBOSE, hexdump(data))
            self.logger.log(VERBOSE, hexdump(sstp))

        assert self.transport is not None
        self.transport.write(sstp)

    def ppp_exited(self) -> None:
        if (
            self.state != State.SERVER_CONNECT_REQUEST_PENDING
            and self.state != State.SERVER_CALL_CONNECTED_PENDING
            and self.state != State.SERVER_CALL_CONNECTED
        ):
            if self.transport:
                self.transport.close()
            return
        self.state = State.CALL_DISCONNECT_IN_PROGRESS_1
        msg = SSTPControlPacket(MsgType.CALL_DISCONNECT)
        msg.attributes = [(SSTP_ATTRIB_NO_ERROR, ATTRIB_STATUS_NO_ERROR)]
        if self.transport:
            msg.write_to(self.transport.write)
        self.state = State.CALL_DISCONNECT_ACK_PENDING
        self.loop.call_later(3, self.close_transport)


class SSTPProtocolFactory:
    protocol = SSTPProtocol

    def __init__(
        self,
        config: Any,
        remote_pool: IPPool | None,
        cert_hash: Fingerprint | None = None,
    ) -> None:
        self.pppd = config.pppd
        self.pppd_config_file = config.pppd_config
        self.local = config.local
        self.proxy_protocol = config.proxy_protocol
        self.use_http_proxy = config.no_ssl and not config.proxy_protocol
        self.remote_pool = remote_pool
        self.cert_hash = cert_hash
        self.logger = logger
        self.log_level = config.log_level

    def __call__(self) -> SSTPProtocol:
        return self.protocol(self)


class SessionLogger(logging.LoggerAdapter):
    def __init__(self, logger, id: str, host: str | None, port: int | None) -> None:
        if host and port:
            if ":" in host:
                tag = f"{id}/[{host}]:{port}"
            else:
                tag = f"{id}/{host}:{port}"
        elif host:
            tag = f"{id}/{host}"
        else:
            tag = id
        super().__init__(logger, dict(tag=tag), False)

    def process(
        self, msg: str, kwargs: MutableMapping[str, Any]
    ) -> tuple[str, MutableMapping[str, Any]]:
        return f"[{self.extra['tag']}] {msg}", kwargs  # type: ignore
