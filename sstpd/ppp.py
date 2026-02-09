import asyncio
import logging
import os
from asyncio.transports import ReadTransport, WriteTransport
from dataclasses import dataclass
from io import FileIO
from logging import Logger
from typing import Callable, TypedDict


class CompoundMacKey(TypedDict, total=False):
    sha1: bytes
    sha256: bytes


@dataclass
class PPPCallback:
    pause_producing: Callable[[], None]
    resume_producing: Callable[[], None]
    data_received: Callable[[bytes], None]
    exited: Callable[[], None]


class PTYReceiver(asyncio.Protocol):
    def __init__(self, pppd: "PPPDProtocol") -> None:
        self.pppd = pppd

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, ReadTransport)
        self.pppd.read_transport = transport

    def data_received(self, data: bytes) -> None:
        self.pppd.callback.data_received(data)

    def connection_lost(self, exc: Exception | None) -> None:
        pass


class PTYSender(asyncio.Protocol):
    def __init__(self, pppd: "PPPDProtocol") -> None:
        self.pppd = pppd

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, WriteTransport)
        self.pppd.write_transport = transport
        transport.set_write_buffer_limits(512 * 1024, 128 * 1024)

    def connection_lost(self, exc: Exception | None) -> None:
        pass

    def pause_writing(self) -> None:
        self.pppd.callback.pause_producing()

    def resume_writing(self) -> None:
        self.pppd.callback.resume_producing()


class PPPDProtocol(asyncio.SubprocessProtocol):
    def __init__(
        self,
        logger: Logger,
        remote: str,
        master_fd: int,
        slave_fd: int,
        callback: PPPCallback,
    ) -> None:
        self.logger = logger
        self.remote = remote
        self.master_fd = master_fd
        self.slave_fd = slave_fd
        self.callback = callback
        self.transport: asyncio.SubprocessTransport | None = None
        self.write_transport: asyncio.WriteTransport | None = None
        self.read_transport: asyncio.ReadTransport | None = None
        self.pty_file: FileIO | None = None
        self.plugin = Plugin(self)

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
        # By default, pppd print log to stdout
        # So we choose stderr to communicate with our plugin
        match fd:
            case 1:  # stdout
                self.logger.info("pppd (stdout): %s", data.decode(errors="replace"))
            case 2:  # stderr
                self.logger.debug("pppd (stderr): %s", data.decode(errors="replace"))
                self.plugin.out_received(data)

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
        self.callback.exited()

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
        self, remote: str, master_fd: int, slave_fd: int, callback: PPPCallback
    ) -> None:
        # TODO: set session info to logger
        self.logger = logging.getLogger("PPPD")
        self.remote = remote
        self.master_fd = master_fd
        self.slave_fd = slave_fd
        self.callback = callback

    def __call__(self) -> PPPDProtocol:
        return PPPDProtocol(
            self.logger,
            self.remote,
            self.master_fd,
            self.slave_fd,
            self.callback,
        )


class Plugin:
    def __init__(self, pppd: "PPPDProtocol") -> None:
        self.pppd = pppd
        self.buffer = bytearray()
        self.loaded = False
        self.has_error = False
        self.cmk = CompoundMacKey()

    def out_received(self, data: bytes) -> None:
        self.buffer.extend(data)
        while True:
            pos = self.buffer.find(b"\n")
            if pos == -1:
                if len(self.buffer) > 2000:
                    self.buffer.clear()
                break
            line = self.buffer[:pos]
            self.buffer = self.buffer[pos + 1 :]
            if line.startswith(b"SSTP:"):
                try:
                    self.line_received(line.decode())
                except UnicodeDecodeError:
                    self.pppd.logger.warning("Failed to decode line")

    def line_received(self, line: str) -> None:
        try:
            _, cmd, value = line.split(":", 2)
        except ValueError:
            self.pppd.logger.warning("Failed to decode plugin cmd: %s", line)
            return
        match cmd:
            case "LOADED":
                self.pppd.logger.info("pppd plugin loaded: %s", value)
                self.loaded = True
            case "ERROR":
                self.error = True
                self.pppd.logger.warning("Plugin error: %s", value)
            case "INFO":
                self.pppd.logger.info("Plugin: %s", value)
            case "CMK":
                try:
                    algo, hex = value.split(":", 1)
                    self.cmk[algo] = bytes.fromhex(hex)
                except ValueError:
                    self.error = True
                    self.pppd.logger.warning("Plugin sent invalid key")
