import asyncio
import os
from asyncio import Transport
from binascii import hexlify
from typing import Any

from .codec import PppDecoder, escape  # type: ignore
from .constants import VERBOSE
from .utils import hexdump

STDIN = 0
STDOUT = 1
STDERR = 2


def is_ppp_control_frame(frame: bytes) -> bool:
    if frame.startswith(b"\xff\x03"):
        protocol = frame[2:4]
    else:
        protocol = frame[:2]
    return protocol[0] in (0x80, 0x82, 0xC0, 0xC2, 0xC4)


class PPPDProtocol(asyncio.SubprocessProtocol):
    def __init__(self) -> None:
        self.decoder = PppDecoder()
        # uvloop not allow pause a paused transport
        self.paused = False
        # for fixing uvloop bug
        self.exited = False
        self.sstp: Any = None
        self.remote: str | None = None
        self.transport: asyncio.SubprocessTransport | None = None
        self.write_transport: asyncio.WriteTransport | None = None
        self.read_transport: asyncio.ReadTransport | None = None

    def write_frame(self, frame: bytes) -> None:
        if self.write_transport:
            self.write_transport.write(escape(frame))

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore
        self.write_transport = transport.get_pipe_transport(STDIN)  # type: ignore
        self.read_transport = transport.get_pipe_transport(STDOUT)  # type: ignore

    def pipe_data_received(self, fd: int, data: bytes) -> None:
        if fd == STDOUT:
            self.out_received(data)
        else:
            self.err_received(data)

    def out_received(self, data: bytes) -> None:
        if __debug__:
            self.sstp.logger.log(VERBOSE, "Raw data: %s", hexdump(data))
        frames = self.decoder.unescape(data)
        self.sstp.write_ppp_frames(frames)

    def err_received(self, data: bytes) -> None:
        self.sstp.logger.warn("Received errors from pppd.")
        self.sstp.logger.warn(data)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is None:
            self.sstp.logger.debug("pppd closed with EoF")
        else:
            self.sstp.logger.info("pppd closed with error: %s", exc)

    def process_exited(self) -> None:
        # uvloop 0.8.0 dosen't call this callback
        if self.transport:
            self._process_exited(self.transport.get_returncode())

    def _process_exited(self, returncode: int | None) -> None:
        if self.exited:
            return
        self.exited = True
        self.sstp.logger.info("pppd exited with code %s.", returncode)
        self.sstp.ppp_stopped()

    def pipe_connection_lost(self, fd: int, exc: Exception | None) -> None:
        if fd != STDOUT:
            return
        # uvloop 0.8.0 dosen't wait for exited pppd process,
        # so we try to wait here
        if self.transport:
            pid = self.transport.get_pid()
        else:
            pid = None

        def wait_pppd() -> None:
            if self.exited:
                return  # not bug, not need to fix
            try:
                if pid is not None:
                    pid_res, returncode = os.waitpid(-1, os.WNOHANG)
                    self._process_exited(-returncode)
            except OSError as e:
                self.sstp.logger.warning("fail to wait for pppd", e)

        asyncio.get_event_loop().call_later(1, wait_pppd)

    def pause_producing(self) -> None:
        if not self.paused:
            self.paused = True
            self.sstp.logger.debug("Pause producting")
            if self.read_transport:
                self.read_transport.pause_reading()

    def resume_producing(self) -> None:
        if self.paused:
            self.paused = False
            self.sstp.logger.debug("Resume producing")
            if self.read_transport:
                self.read_transport.resume_reading()


class PPPDProtocolFactory:
    def __init__(self, callback: Any, remote: str) -> None:
        self.sstp = callback
        self.remote = remote

    def __call__(self) -> PPPDProtocol:
        proto = PPPDProtocol()
        proto.sstp = self.sstp
        proto.remote = self.remote
        return proto


class PPPDSSTPAPIProtocol(asyncio.Protocol):
    SSTP_API_MSG_UNKNOWN = 0
    SSTP_API_MSG_AUTH = 1
    SSTP_API_MSG_ADDR = 2
    SSTP_API_MSG_ACK = 3

    message_str = {
        SSTP_API_MSG_UNKNOWN: "SSTP_API_MSG_UNKNOWN",
        SSTP_API_MSG_AUTH: "SSTP_API_MSG_AUTH",
        SSTP_API_MSG_ADDR: "SSTP_API_MSG_ADDR",
        SSTP_API_MSG_ACK: "SSTP_API_MSG_ACK",
    }

    SSTP_API_ATTR_UNKNOWN = 0
    SSTP_API_ATTR_MPPE_SEND = 1
    SSTP_API_ATTR_MPPE_RECV = 2
    SSTP_API_ATTR_GATEWAY = 3
    SSTP_API_ATTR_ADDR = 4

    attribute_str = {
        SSTP_API_ATTR_UNKNOWN: "SSTP_API_ATTR_UNKNOWN",
        SSTP_API_ATTR_MPPE_SEND: "SSTP_API_ATTR_MPPE_SEND",
        SSTP_API_ATTR_MPPE_RECV: "SSTP_API_ATTR_MPPE_RECV",
        SSTP_API_ATTR_GATEWAY: "SSTP_API_ATTR_GATEWAY",
        SSTP_API_ATTR_ADDR: "SSTP_API_ATTR_ADDR",
    }

    def __init__(self) -> None:
        self.sstp: Any = None
        self.master_send_key: bytes | None = None
        self.master_recv_key: bytes | None = None
        self.transport: Transport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        sockname = transport.get_extra_info("sockname")
        if self.sstp:
            self.sstp.logger.info("Initiate PPP SSTP API protocol on %s.", sockname)
        assert isinstance(transport, Transport)
        self.transport = transport

    def message_type(self, mtype: int) -> str:
        return self.message_str.get(mtype, self.message_str[self.SSTP_API_MSG_UNKNOWN])

    def is_auth_message(self, mtype: int) -> bool:
        return mtype is self.SSTP_API_MSG_AUTH

    def attribute_type(self, atype: int) -> str:
        return self.attribute_str.get(
            atype, self.attribute_str[self.SSTP_API_ATTR_UNKNOWN]
        )

    def is_mppe_send_attribute(self, atype: int) -> bool:
        return atype is self.SSTP_API_ATTR_MPPE_SEND

    def is_mppe_recv_attribute(self, atype: int) -> bool:
        return atype is self.SSTP_API_ATTR_MPPE_RECV

    def handle_attribute(self, atype: int, adata: bytes) -> None:
        if self.is_mppe_send_attribute(atype):
            self.master_send_key = adata
            if __debug__:
                self.sstp.logger.debug(
                    "PPP master send key %s", hexlify(self.master_send_key)
                )
        elif self.is_mppe_recv_attribute(atype):
            self.master_recv_key = adata
            if __debug__:
                self.sstp.logger.debug(
                    "PPP master receive key %s", hexlify(self.master_recv_key)
                )

    def message_parse(self, message: bytes) -> bool:
        idx = 0
        while idx < len(message):
            if idx + 4 > len(message):
                break
            atype = (message[idx + 1] << 8) | message[idx]
            alen = (message[idx + 3] << 8) | message[idx + 2]
            self.sstp.logger.debug(
                "SSTP API message - attribute %s (len: %d)",
                self.attribute_type(atype),
                alen,
            )
            idx += 4
            self.handle_attribute(atype, message[idx : idx + alen])
            idx += alen

        return idx == len(message)

    def data_received(self, data: bytes) -> None:
        # magic 'sstp' as 32-bits integer in network order
        magic = b"\x70\x74\x73\x73"
        # ack whatever received and close connection
        ack = magic + b"\x00\x00" + b"\x03\x00"
        if self.transport:
            self.transport.write(ack)
        self.close()
        if data[0:4] != magic:
            self.sstp.logger.error("SSTP API message - invalid magic %a.", data[0:4])
            return
        length = (data[5] << 8) | data[4]
        if length + 8 != len(data):
            self.sstp.logger.error("SSTP API message - incorrect length.")
            return
        if not self.message_parse(data[8:]):
            self.sstp.logger.error("SSTP API message - failed parsing attributes.")
            return
        mtype = (data[7] << 8) | data[6]
        if self.is_auth_message(mtype):
            if self.master_send_key is None or self.master_recv_key is None:
                self.sstp.logger.error(
                    "SSTP API message - missing master send and/or receive key."
                )
                return
        self.sstp.higher_layer_authentication_key_received(
            self.master_send_key, self.master_recv_key
        )

    def close(self) -> None:
        self.sstp.logger.info("Finished PPP SSTP API protocol.")
        if self.transport:
            self.transport.close()


class PPPDSSTPPluginFactory:
    def __init__(self, callback: Any) -> None:
        self.sstp = callback

    def __call__(self) -> PPPDSSTPAPIProtocol:
        proto = PPPDSSTPAPIProtocol()
        proto.sstp = self.sstp
        return proto
