import os
import logging
from struct import pack
import asyncio

from .constants import VERBOSE
from .codec import escape, PppDecoder
from .utils import hexdump


STDIN = 0
STDOUT = 1
STDERR = 2

def is_ppp_control_frame(frame):
    if frame.startswith(b'\xff\x03'):
        protocol = frame[2:4]
    else:
        protocol = frame[:2]
    return protocol[0] in (0x80, 0x82, 0xc0, 0xc2, 0xc4)

class PPPDProtocol(asyncio.SubprocessProtocol):

    def __init__(self):
        self.decoder = PppDecoder()
        # uvloop not allow pause a paused transport
        self.paused = False
        # for fixing uvloop bug
        self.exited = False

    def write_frame(self, frame):
        self.write_transport.write(escape(frame))

    def connection_made(self, transport):
        self.transport = transport
        self.write_transport = transport.get_pipe_transport(STDIN)
        self.read_transport = transport.get_pipe_transport(STDOUT)

    def pipe_data_received(self, fd, data):
        if fd == STDOUT:
            self.out_received(data)
        else:
            self.err_received(data)

    def out_received(self, data):
        if __debug__:
            logging.log(VERBOSE, "Raw data: %s", hexdump(data))
        frames = self.decoder.unescape(data)
        self.sstp.write_ppp_frames(frames)

    def err_received(self, data):
        logging.warn('Received errors from pppd.')
        logging.warn(data)

    def connection_lost(self, err):
        if err is None:
            logging.debug('pppd closed with EoF')
        else:
            logging.info('pppd closed with error: %s', err)

    def process_exited(self):
        # uvloop 0.8.0 dosen't call this callback
        self._process_exited(self.transport.get_returncode())

    def _process_exited(self, returncode):
        if self.exited:
            return
        self.exited = True
        logging.info('pppd exited with code %s.', returncode)
        self.sstp.ppp_stopped()

    def pipe_connection_lost(self, fd, exc):
        if fd != STDOUT:
            return
        # uvloop 0.8.0 dosen't wait for exited pppd process,
        # so we try to wait here
        pid = self.transport.get_pid()
        def wait_pppd():
            if self.exited:
                return  # not bug, not need to fix
            try:
                pid, returncode = os.waitpid(-1, os.WNOHANG)
                self._process_exited(-returncode)
            except OSError as e:
                logging.warning("fail to wait for pppd", e)
        asyncio.get_event_loop().call_later(1, wait_pppd)

    def pause_producing(self):
        if not self.paused:
            self.paused = True
            logging.debug('Pause producting')
            self.read_transport.pause_reading()

    def resume_producing(self):
        if self.paused:
            self.paused = False
            logging.debug('Resume producing')
            self.read_transport.resume_reading()


class PPPDProtocolFactory:
    def __init__(self, callback, remote):
        self.sstp = callback
        self.remote = remote

    def __call__(self):
        proto = PPPDProtocol()
        proto.sstp = self.sstp
        proto.remote = self.remote
        return proto
