import os
import struct
import logging
from twisted.internet.protocol import Factory, Protocol, ProcessProtocol
from twisted.internet import reactor

from constants import *
from packets import SSTPDataPacket, SSTPControlPacket
from utils import hexdump, parseLength


class PPPDProtocol(ProcessProtocol):
    reciveBuffer = ''
    pppFrameLength = 0

    def outReceived(self, data):
        self.reciveBuffer += data
        while len(self.reciveBuffer) >= 6:
            # Get length of frame if necessary.
            if not self.pppFrameLength:
                if self.reciveBuffer.startswith('\xff\x03'):
                    if len(self.reciveBuffer) < 8:
                        return
                    length = self.reciveBuffer[6:8]
                    headerLength = 4
                else:
                    length = self.reciveBuffer[4:6]
                    headerLength = 2
                self.pppFrameLength = struct.unpack('!H', length)[0] \
                        + headerLength

            if len(self.reciveBuffer) < self.pppFrameLength:
                return
            self.pppFrameReceived(self.reciveBuffer[:self.pppFrameLength])
            self.reciveBuffer = self.reciveBuffer[self.pppFrameLength:]
            self.pppFrameLength = 0


    def pppFrameReceived(self, frame):
        if frame.startswith('\xff\x03'):
            protocol = frame[2:4]
        else:
            protocol = frame[:2]
        if ord(protocol[0]) < ord('\x80'):
            self.pppDataFrameReceived(frame)
        else:
            self.pppControlFrameReceived(frame)


    def pppControlFrameReceived(self, frame):
        logging.debug('PPP control frame received (%s bytes).' % len(frame))
        if self.sstp.state == SERVER_CALL_CONNECTED_PENDING or \
                self.sstp.state == SERVER_CALL_CONNECTED:
            packet = SSTPDataPacket(frame)
            self.sstp.transport.write(packet.dump())


    def pppDataFrameReceived(self, frame):
        logging.debug('PPP data frame received (%s bytes).' % len(frame))
        if self.sstp.state == SERVER_CALL_CONNECTED:
            packet = SSTPDataPacket(frame)
            self.sstp.transport.write(packet.dump())


    def errReceived(self, data):
        logging.warn('Received errors from pppd.')
        logging.warn(data)


    def outConnectionLost(self):
        logging.debug('pppd stdout lost.')
        self.sstp.transport.loseConnection()


    def processEnded(self, reason):
        logging.info('pppd stopped.')
        if (self.sstp.state != SERVER_CONNECT_REQUEST_PENDING and
                self.sstp.state != SERVER_CALL_CONNECTED_PENDING and
                self.sstp.state != SERVER_CALL_CONNECTED):
            self.sstp.transport.loseConnection()
            return
        self.sstp.state = CALL_DISCONNECT_IN_PROGRESS_1
        msg = SSTPControlPacket(SSTP_MSG_CALL_DISCONNECT)
        msg.attributes = [(SSTP_ATTRIB_NO_ERROR, ATTRIB_STATUS_NO_ERROR)]
        self.sstp.transport.write(msg.dump())
        self.sstp.state = CALL_DISCONNECT_ACK_PENDING
        reactor.callLater(5, self.sstp.transport.loseConnection)


class SSTPProtocol(Protocol):
    state = SERVER_CALL_DISCONNECTED
    sstpPacketLength = 0
    reciveBuffer = ''
    nonce = None
    pppd = None
    retryCounter = 0

    def __init__(self):
        self.helloTimer = reactor.callLater(60, self.helloTimerExpired)


    def dataReceived(self, data):
        if self.state == SERVER_CALL_DISCONNECTED:
            self.httpDataReceived(data)
        else:
            self.sstpDataReceived(data)


    def connectionLost(self, reason):
        logging.info('Connection finished.')
        if self.pppd is not None:
            self.pppd.transport.loseConnection()
        if self.helloTimer.active():
            self.helloTimer.cancel()


    def httpDataReceived(self, data):
        self.reciveBuffer += data
        if "\r\n\r\n" not in self.reciveBuffer:
            return
        requestLine = self.reciveBuffer.split('\r\n')[0]
        self.reciveBuffer = ''
        method, uri, version = requestLine.split()
        if method != "SSTP_DUPLEX_POST" and version != "HTTP/1.1":
            logging.warn('Unexpected HTTP method and/or version.')
            self.transport.loseConnection()
            return
        self.transport.write('HTTP/1.1 200 OK\r\n'
                'Content-Length: 18446744073709551615\r\n'
                'Server: sorztest/0.1\r\n\r\n')
        self.state = SERVER_CONNECT_REQUEST_PENDING


    def sstpDataReceived(self, data):
        self.reciveBuffer += data
        while len(self.reciveBuffer) >= 4:
            # Check version.
            if self.reciveBuffer[0] != '\x10':
                logging.warn('Unsupported SSTP version.')
                self.transport.loseConnection()
                return
            # Get length if necessary.
            if not self.sstpPacketLength:
                self.sstpPacketLength = parseLength(self.reciveBuffer[2:4])
            if len(self.reciveBuffer) < self.sstpPacketLength:
                return
            packet = self.reciveBuffer[:self.sstpPacketLength]
            self.reciveBuffer = self.reciveBuffer[self.sstpPacketLength:]
            self.sstpPacketLength = 0
            self.sstpPacketReceived(packet)


    def sstpPacketReceived(self, packet):
        self.helloTimer.reset(60)
        c = ord(packet[1]) & 0x01
        if c == 0:  # Data packet
            self.sstpDataPacketReceived(packet[4:])
        else:  # Control packet
            messageType = packet[4:6]
            numAttributes = struct.unpack('!H', packet[6:8])[0]
            attributes = []
            attrs = packet[8:]
            while len(attributes) < numAttributes:
                id = attrs[1]
                length = parseLength(attrs[2:4])
                value = attrs[4:length]
                attrs = attrs[length:]
                attributes.append((id, value))
            self.sstpControlPacketReceived(messageType, attributes)


    def sstpDataPacketReceived(self, data):
        logging.debug('Forwarding SSTP data to pppd (%s bytes).' % len(data))
        if self.pppd is None:
            print('pppd is None.')
            return
        self.pppd.transport.write(data)


    def sstpControlPacketReceived(self, messageType, attributes):
        logging.info('SSTP control packet (type %s) received.' % ord(messageType[1]))
        if messageType == SSTP_MSG_CALL_CONNECT_REQUEST:
            protocolId = attributes[0][1]
            self.sstpMsgCallConnectRequestReceived(protocolId)
        elif messageType == SSTP_MSG_CALL_CONNECTED:
            attr = attributes[0][1]
            hashType = attr[3:4]
            nonce = attr[4:36]
            certHash = attr[36:68]
            macHash = attr[68:72]
            self.sstpMsgCallConnectedReceived(hashType, nonce, certHash, macHash)
        elif messageType == SSTP_MSG_CALL_ABORT:
            if attributes:
                self.sstpMsgCallAbort(attributes[0][1])
            else:
                self.sstpMsgCallAbort()
        elif messageType == SSTP_MSG_CALL_DISCONNECT:
            if attributes:
                self.sstpMsgCallDisconnect(attributes[0][1])
            else:
                self.sstpMsgCallDisconnect()
        elif messageType == SSTP_MSG_CALL_DISCONNECT_ACK:
            self.sstpMsgCallDisconnectAck()
        elif messageType == SSTP_MSG_ECHO_REQUEST:
            self.sstpMsgEchoRequest()
        elif messageType == SSTP_MSG_ECHO_RESPONSE:
            self.sstpMsgEchoResponse()
        else:
            logging.warn('Unknown type of SSTP control packet.')
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)


    def sstpMsgCallConnectRequestReceived(self, protocolId):
        if self.state != SERVER_CONNECT_REQUEST_PENDING:
            print('Not in the state.')
            self.transport.loseConnection()
            return
        if protocolId != SSTP_ENCAPSULATED_PROTOCOL_PPP:
            print('Unsupported encapsulated protocol.')
            nak = SSTPControlPacket(SSTP_MSG_CALL_CONNECT_NAK)
            nak.attributes = [(SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID,
                    ATTRIB_STATUS_VALUE_NOT_SUPPORTED)]
            self.addRetryCounterOrAbrot()
            return
        self.nonce = os.urandom(32)
        ack = SSTPControlPacket(SSTP_MSG_CALL_CONNECT_ACK)
        ack.attributes = [(SSTP_ATTRIB_CRYPTO_BINDING_REQ,
                '\x00\x00\x00' + '\x03' + self.nonce)]
        self.transport.write(ack.dump())
        self.pppd = PPPDProtocol()
        self.pppd.sstp = self
        reactor.spawnProcess(self.pppd, self.factory.pppd,
                args=['local', 'notty','file', self.factory.pppdConfigFile,
                    '115200', '10.10.25.1:10.10.25.50',
                    'ipparam', '202.86.179.90',
                    'remotenumber', '202.86.179.90'],
                usePTY=False, childFDs={0:'w', 1:'r', 2:'r'})
        self.state = SERVER_CALL_CONNECTED_PENDING


    def sstpMsgCallConnectedReceived(self, hashType, nonce, certHash, macHash):
        if self.state != SERVER_CALL_CONNECTED_PENDING:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)
        if nonce != self.nonce:
            logging.warn('Received wrong nonce.')
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return
        self.nonce = None
        # TODO: check certHash and macHash
        self.state = SERVER_CALL_CONNECTED
        logging.info('Connection established.')


    def sstpMsgCallAbort(self, status=None):
        logging.warn("Call abort.")
        if self.state == CALL_ABORT_PENDING:
            reactor.callLater(1, self.transport.loseConnection)
            return
        self.state = CALL_ABORT_IN_PROGRESS_2
        msg = SSTPControlPacket(SSTP_MSG_CALL_ABORT)
        self.transport.write(msg.dump())
        self.state = CALL_ABORT_PENDING
        reactor.callLater(1, self.transport.loseConnection)


    def sstpMsgCallDisconnect(self, status=None):
        logging.info('Received call disconnect request.')
        self.state = CALL_DISCONNECT_IN_PROGRESS_2
        ack = SSTPControlPacket(SSTP_MSG_CALL_DISCONNECT_ACK)
        self.transport.write(ack.dump())
        self.state = CALL_DISCONNECT_TIMEOUT_PENDING
        reactor.callLater(1, self.transport.loseConnection)


    def sstpMsgCallDisconnectAck(self):
        self.transport.loseConnection()


    def sstpMsgEchoRequest(self):
        response = SSTPControlPacket(SSTP_MSG_ECHO_RESPONSE)
        self.transport.write(response)


    def sstpMsgEchoResponse(self):
        self.helloTimer = reactor.callLater(60, self.helloTimerExpired)


    def helloTimerExpired(self, close=False):
        if self.state == SERVER_CALL_DISCONNECTED:
            self.transport.loseConnection()  # TODO: follow HTTP
        elif close:
            logging.warn('Ping time out.')
            self.abort(ATTRIB_STATUS_NEGOTIATION_TIMEOUT)
        else:
            logging.info('Send echo request.')
            echo = SSTPControlPacket(SSTP_MSG_ECHO_REQUEST)
            self.transport.write(echo.dump())
            self.helloTimer = reactor.callLater(60, self.helloTimerExpired, True)


    def addRetryCounterOrAbrot(self):
        self.retryCounter += 1
        if self.retryCounter > 3:
            self.abort(ATTRIB_STATUS_RETRY_COUNT_EXCEEDED)


    def abort(self, status=None):
        if status is None:
            logging.warn('Abort.')
        else:
            logging.warn('Abort (%s).' % ord(status[-1]))
        self.state = CALL_DISCONNECT_IN_PROGRESS_1
        msg = SSTPControlPacket(SSTP_MSG_CALL_ABORT)
        if status is not None:
            msg.attributes = [(SSTP_ATTRIB_STATUS_INFO, status)]
        self.transport.write(msg.dump())
        self.state = CALL_ABORT_PENDING
        reactor.callLater(3, self.transport.loseConnection)


class SSTPProtocolFactory(Factory):
    protocol = SSTPProtocol

    def __init__(self, pppd, pppdConfigFile):
        self.pppd = pppd
        self.pppdConfigFile = pppdConfigFile

