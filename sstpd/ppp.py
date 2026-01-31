import asyncio
import logging
import os
from io import FileIO
from logging import Logger

from .codec import PppDecoder, escape
from .constants import VERBOSE
from .utils import hexdump


def is_ppp_control_frame(frame: memoryview | bytearray) -> bool:
    if frame[0] == 0xFF and frame[1] == 0x03:
        protocol = frame[2:4]
    else:
        protocol = frame[:2]
    return protocol[0] in (0x80, 0x82, 0xC0, 0xC2, 0xC4)


class PTYReceiver(asyncio.Protocol):
    def __init__(self, pppd: "PPPDProtocol") -> None:
        self.pppd = pppd

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.pppd.read_transport = transport  # type: ignore

    def data_received(self, data: bytes) -> None:
        self.pppd.out_received(data)

    def connection_lost(self, exc: Exception | None) -> None:
        pass


class PTYSender(asyncio.Protocol):
    def __init__(self, pppd: "PPPDProtocol") -> None:
        self.pppd = pppd

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.pppd.write_transport = transport  # type: ignore

    def connection_lost(self, exc: Exception | None) -> None:
        pass


class PPPDProtocol(asyncio.SubprocessProtocol):
    def __init__(
        self,
        logger: Logger,
        sstp: "SSTPProtocol",
        remote: str,
        master_fd: int,
        slave_fd: int,
    ) -> None:
        self.logger = logger
        self.sstp = sstp
        self.remote = remote
        self.master_fd = master_fd
        self.slave_fd = slave_fd
        self.decoder = PppDecoder()
        self.transport: asyncio.SubprocessTransport | None = None
        self.write_transport: asyncio.WriteTransport | None = None
        self.read_transport: asyncio.ReadTransport | None = None
        self.pty_file: FileIO | None = None

    def write_frame(self, frame: bytes) -> None:
        if self.write_transport:
            self.write_transport.write(escape(frame))

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.SubprocessTransport)
        self.transport = transport
        loop = asyncio.get_event_loop()
        asyncio.ensure_future(self.setup_pty(loop))

    async def setup_pty(self, loop: asyncio.AbstractEventLoop) -> None:
        try:
            os.set_blocking(self.master_fd, False)
            self.pty_file = os.fdopen(self.master_fd, "rb+", buffering=0)
            await loop.connect_read_pipe(lambda: PTYReceiver(self), self.pty_file)
            await loop.connect_write_pipe(lambda: PTYSender(self), self.pty_file)
        except Exception as e:
            self.logger.error("Error setting up PTY: %s", e)
            if self.transport is not None:
                self.transport.kill()

    def pipe_data_received(self, fd: int, data: bytes) -> None:
        self.logger.info("pppd says (%s) %s", fd, data)

    def out_received(self, data: bytes) -> None:
        if self.logger.isEnabledFor(VERBOSE):
            self.logger.log(VERBOSE, "Raw data: %s", hexdump(data))
        frames = self.decoder.unescape(data)
        self.sstp.write_ppp_frames(frames)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is None:
            self.logger.debug("pppd closed with EoF")
        else:
            self.logger.info("pppd closed with error: %s", exc)
        if self.read_transport is not None:
            self.read_transport.close()
        if self.write_transport is not None:
            self.write_transport.close()
        try:
            os.close(self.slave_fd)
        except OSError as err:
            self.logger.warning("pty slave close error: %s", err)
        if self.pty_file is None:
            try:
                os.close(self.master_fd)
            except OSError as err:
                self.logger.warning("pty master close error: %s", err)
        else:
            self.pty_file.close()

    def process_exited(self) -> None:
        if self.transport is not None:
            returncode = self.transport.get_returncode()
            self.logger.info("pppd exited with code %s", returncode)
        self.sstp.ppp_stopped()

    def pause_producing(self) -> None:
        self.logger.debug("Pause producting")
        if self.read_transport:
            self.read_transport.pause_reading()

    def resume_producing(self) -> None:
        self.logger.debug("Resume producing")
        if self.read_transport:
            self.read_transport.resume_reading()


class PPPDProtocolFactory:
    def __init__(
        self,
        sstp: "SSTPProtocol",
        remote: str,
        master_fd: int,
        slave_fd: int,
    ) -> None:
        # TODO: set session info to logger
        self.logger = logging.getLogger("PPPD")
        self.sstp = sstp
        self.remote = remote
        self.master_fd = master_fd
        self.slave_fd = slave_fd

    def __call__(self) -> PPPDProtocol:
        return PPPDProtocol(
            self.logger, self.sstp, self.remote, self.master_fd, self.slave_fd
        )
