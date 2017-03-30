import logging
from struct import pack
from zope.interface import implements
from twisted.internet.protocol import ProcessProtocol
from twisted.internet import reactor, interfaces

from constants import VERBOSE
from codec import unescape, escape
from utils import hexdump


class PPPDProtocol(ProcessProtocol):
    implements(interfaces.IPushProducer)

    def __init__(self, sync):
        self.frameBuffer = b''
        self.frameEscaped = False
        self.paused = False
        self.sync = sync


    def writeFrame(self, frame):
        if self.sync:
            self.transport.write(frame)
        else:
            self.transport.write(escape(frame))


    def outReceived(self, data):
        if __debug__:
            logging.log(VERBOSE, "Raw data: %s", hexdump(data))
        if self.sync:
            data = self.frameBuffer + data
            self.frameBuffer = b''
            start = 0
            while start < len(data):
                if data[start] == '\xff':
                    length = ord(data[start+6]) << 8 | ord(data[start+7])
                    length += 4
                elif data[start] not in ('\xff', '\x80', '\x82', '\xc0', '\xc2', '\xc4'):
                    length = ord(data[start+3]) << 8 | ord(data[start+4])
                    length += 1  # proto no. on first byte
                    #logging.info("length: %s", length)
                else:
                    length = len(data) - start
                if start + length <= len(data):
                    self.pppFrameReceived(data[start:start+length])
                else:
                    self.frameBuffer = data[start:]
                start += length
        else:
            frames, self.frameBuffer, self.frameEscaped = \
                    unescape(data, self.frameBuffer, self.frameEscaped)
            for frame in frames:
                self.pppFrameReceived(frame)


    def pppFrameReceived(self, frame):
        if self.paused:
            logging.debug('Drop a PPP frame.')
            return

        if frame.startswith('\xff\x03'):
            protocol = frame[2:4]
        else:
            protocol = frame[:2]

        if protocol[0] in ('\x80', '\x82', '\xc0', '\xc2', '\xc4'):
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

