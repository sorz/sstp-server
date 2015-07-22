import logging
from struct import pack
from zope.interface import implements
from twisted.internet.protocol import ProcessProtocol
from twisted.internet import reactor, interfaces

from constants import VERBOSE
from codec import unescape, pppfcs16
from utils import hexdump


FLAG_SEQUENCE = b'\x7e'
CONTROL_ESCAPE = b'\x7d'

class PPPDProtocol(ProcessProtocol):
    implements(interfaces.IPushProducer)

    frameBuffer = b''
    paused = False

    def writeFrame(self, frame):
        fcs = pppfcs16(frame)
        buffer = bytearray(FLAG_SEQUENCE)
        for byte in frame:
            if ord(byte) < 0x20 or byte in (FLAG_SEQUENCE, CONTROL_ESCAPE):
                buffer.append(CONTROL_ESCAPE)
                buffer.append(ord(byte) ^ 0x20)
            else:
                buffer.append(byte)

        buffer.extend(pack('!H', fcs))
        buffer.append(FLAG_SEQUENCE)
        self.transport.write(str(buffer))


    def outReceived(self, data):
        logging.log(VERBOSE, "Raw data: %s", hexdump(data))
        frames, self.frameBuffer = unescape(data, self.frameBuffer)
        logging.debug("data %s bytes => %s frames", len(data), len(frames))
        for frame in frames:
            self.pppFrameReceived(bytearray(frame))


    def pppFrameReceived(self, frame):
        if self.paused:
            logging.debug('Drop a PPP frame.')
            return

        if frame.startswith('\xff\x03'):
            protocol = frame[2:4]
        else:
            protocol = frame[:2]

        if protocol[0] in (0x80, 0x82, 0xc0, 0xc2, 0xc4):
            self.sstp.writePPPControlFrame(frame)
        else:
            self.sstp.writePPPDataFrame(frame)


    def errReceived(self, data):
        logging.warn('Received errors from pppd.')
        logging.warn(data)


    def outConnectionLost(self):
        logging.debug('pppd stdout lost.')
        self.sstp.transport.loseConnection()


    def processEnded(self, reason):
        logging.info('pppd stopped.')
        self.sstp.pppStoped()


    def stopProducing(self):
        self.paused = True
        self.transport.loseConnection()


    def pauseProducing(self):
        logging.debug('Pause producting')
        self.paused = True


    def resumeProducing(self):
        logging.debug('Resume producing')
        self.paused = False

