import logging
from struct import pack
import asyncio

from .constants import VERBOSE
from .codec import unescape, escape
from .utils import hexdump


STDIN = 0
STDOUT = 1
STDERR = 2

class PPPDProtocol(asyncio.SubprocessProtocol):

    def __init__(self):
        self.frame_buf = b''
        self.frame_escaped = False

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
        frames, self.frame_buf, self.frame_escaped = \
                unescape(data, self.frame_buf, self.frame_escaped)
        for frame in frames:
            self.ppp_frame_received(frame)

    def ppp_frame_received(self, frame):
        if frame.startswith(b'\xff\x03'):
            protocol = frame[2:4]
        else:
            protocol = frame[:2]

        if protocol[0] in (0x80, 0x82, 0xc0, 0xc2, 0xc4):
            self.sstp.write_ppp_control_frame(frame)
        else:
            self.sstp.write_ppp_data_frame(frame)

    def err_received(self, data):
        logging.warn('Received errors from pppd.')
        logging.warn(data)

    def pipe_connection_lost(self, fd, err):
        logging.debug('pppd stdin/out lost: %s', err)
        self.transport.close()

    def process_exited(self):
        logging.info('pppd exited with code %s.',
                     self.transport.get_returncode())
        self.sstp.ppp_stopped()

    def pause_producing(self):
        logging.debug('Pause producting')
        self.read_transport.pause_reading()

    def resume_producing(self):
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
