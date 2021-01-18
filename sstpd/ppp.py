import os
import logging
from struct import pack
import asyncio
from binascii import hexlify

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


class PPPDSSTPAPIProtocol(asyncio.Protocol):
    SSTP_API_MSG_UNKNOWN = 0
    SSTP_API_MSG_AUTH    = 1
    SSTP_API_MSG_ADDR    = 2
    SSTP_API_MSG_ACK     = 3

    message_str = {
            SSTP_API_MSG_UNKNOWN: 'SSTP_API_MSG_UNKNOWN',
            SSTP_API_MSG_AUTH:    'SSTP_API_MSG_AUTH',
            SSTP_API_MSG_ADDR:    'SSTP_API_MSG_ADDR',
            SSTP_API_MSG_ACK:     'SSTP_API_MSG_ACK', }

    SSTP_API_ATTR_UNKNOWN   = 0
    SSTP_API_ATTR_MPPE_SEND = 1
    SSTP_API_ATTR_MPPE_RECV = 2
    SSTP_API_ATTR_GATEWAY   = 3
    SSTP_API_ATTR_ADDR      = 4

    attribute_str = {
            SSTP_API_ATTR_UNKNOWN:   'SSTP_API_ATTR_UNKNOWN',
            SSTP_API_ATTR_MPPE_SEND: 'SSTP_API_ATTR_MPPE_SEND',
            SSTP_API_ATTR_MPPE_RECV: 'SSTP_API_ATTR_MPPE_RECV',
            SSTP_API_ATTR_GATEWAY:   'SSTP_API_ATTR_GATEWAY',
            SSTP_API_ATTR_ADDR:      'SSTP_API_ATTR_ADDR', }

    def __init__(self):
        self.sstp = None
        self.master_send_key = None
        self.master_recv_key = None

    def connection_made(self, transport):
        sockname = transport.get_extra_info('sockname')
        logging.info('Initiate PPP SSTP API protocol on %s.', sockname)
        self.transport = transport

    def message_type(self, mtype):
        return self.message_str.get(mtype,
                self.message_str[self.SSTP_API_MSG_UNKNOWN])

    def is_auth_message(self, mtype):
        return mtype is self.SSTP_API_MSG_AUTH

    def attribute_type(self, atype):
        return self.attribute_str.get(atype,
                self.attribute_str[self.SSTP_API_ATTR_UNKNOWN])

    def is_mppe_send_attribute(self, atype):
        return atype is self.SSTP_API_ATTR_MPPE_SEND

    def is_mppe_recv_attribute(self, atype):
        return atype is self.SSTP_API_ATTR_MPPE_RECV

    def handle_attribute(self, atype, adata):
        if self.is_mppe_send_attribute(atype):
            self.master_send_key = adata
            if __debug__:
                logging.debug("PPP master send key %s",
                        hexlify(self.master_send_key))
        elif self.is_mppe_recv_attribute(atype):
            self.master_recv_key = adata
            if __debug__:
                logging.debug("PPP master receive key %s",
                        hexlify(self.master_recv_key))

    def message_parse(self, message):
        idx = 0
        while idx < len(message):
            if (idx + 4 > len(message)):
                break
            atype = (message[idx+1] << 8) | message[idx]
            alen = (message[idx+3] << 8) | message[idx+2]
            logging.debug("SSTP API message - attribute %s (len: %d)",
                    self.attribute_type(atype), alen)
            idx += 4
            self.handle_attribute(atype, message[idx:idx + alen])
            idx += alen

        return (idx == len(message))

    def data_received(self, message):
        # magic 'sstp' as 32-bits integer in network order
        magic = b'\x70\x74\x73\x73'
        # ack whatever received and close connection
        ack = magic + b'\x00\x00' + b'\x03\x00'
        self.transport.write(ack)
        self.close()
        if message[0:4] != magic:
            logging.error("SSTP API message - invalid magic %a.", message[0:4])
            return
        length = (message[5] << 8) | message[4]
        if length + 8 != len(message):
            logging.error("SSTP API message - incorrect length.")
            return
        if not self.message_parse(message[8:]) :
            logging.error("SSTP API message - failed parsing attributes.")
            return
        mtype = (message[7] << 8) | message[6]
        if self.is_auth_message(mtype):
            if (self.master_send_key is None or
                    self.master_recv_key is None):
                logging.error("SSTP API message - missing master "
                        "send and/or receive key.")
                return
        self.sstp.higher_layer_authentication_key(
                self.master_send_key, self.master_recv_key)

    def close(self):
        logging.info('Finished PPP SSTP API protocol.')
        self.transport.close()


class PPPDSSTPPluginFactory:
    def __init__(self, callback):
        self.sstp = callback

    def __call__(self):
        proto = PPPDSSTPAPIProtocol()
        proto.sstp = self.sstp
        return proto
