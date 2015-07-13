import os
import struct
import logging
from twisted.internet.protocol import Factory, Protocol, ProcessProtocol
from twisted.internet import reactor

from constants import *
from packets import SSTPDataPacket, SSTPControlPacket
from fcs import pppfcs16
from utils import hexdump, parseLength


VERBOSE = 5  # log level

FLAG_SEQUENCE = b'\x7e'
CONTROL_ESCAPE = b'\x7d'

class PPPDProtocol(ProcessProtocol):
    frameBuffer = bytearray()

    def writeFrame(self, frame):
        fcs = pppfcs16(frame)
        buffer = bytearray(FLAG_SEQUENCE)
        for byte in frame:
            if ord(byte) < 0x20 or byte in (FLAG_SEQUENCE, CONTROL_ESCAPE):
                buffer.append(CONTROL_ESCAPE)
                buffer.append(ord(byte) ^ 0x20)
            else:
                buffer.append(byte)

        buffer.extend(fcs)
        buffer.append(FLAG_SEQUENCE)
        self.transport.write(str(buffer))


    def outReceived(self, data):
        logging.log(VERBOSE, "Raw data: %s", hexdump(data))
        escaped = False
        for byte in data:
            if escaped:
                escaped = False
                self.frameBuffer.append(ord(byte) ^ 0x20)
            elif byte == CONTROL_ESCAPE:
                escaped = True
            elif byte == FLAG_SEQUENCE:
                if not self.frameBuffer:
                    continue
                if len(self.frameBuffer) < 4:
                    logging.warning("Invalid PPP frame received from pppd. (%s)",
                                    hexdump(self.frameBuffer))
                elif self.frameBuffer:
                    del self.frameBuffer[-2:]  # Remove FCS field
                    self.pppFrameReceived(self.frameBuffer)
                self.frameBuffer = bytearray()
            else:
                self.frameBuffer.append(byte)


    def pppFrameReceived(self, frame):
        logging.log(VERBOSE, "Frame: %s", hexdump(frame))
        if frame.startswith('\xff\x03'):
            protocol = frame[2:4]
        else:
            protocol = frame[:2]
        if protocol[0] in (0x80, 0x82, 0xc0, 0xc2, 0xc4):
            self.pppControlFrameReceived(frame)
        else:
            self.pppDataFrameReceived(frame)


    def pppControlFrameReceived(self, frame):
        logging.debug('PPP control frame received (%s bytes).' % len(frame))
        logging.log(VERBOSE, hexdump(frame))
        if self.sstp.state == SERVER_CALL_CONNECTED_PENDING or \
                self.sstp.state == SERVER_CALL_CONNECTED:
            packet = SSTPDataPacket(frame)
            packet.writeTo(self.sstp.transport.write)


    def pppDataFrameReceived(self, frame):
        logging.debug('PPP data frame received (%s bytes).' % len(frame))
        logging.log(VERBOSE, hexdump(frame))
        if self.sstp.state == SERVER_CALL_CONNECTED:
            packet = SSTPDataPacket(frame)
            packet.writeTo(self.sstp.transport.write)


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
        msg.writeTo(self.sstp.transport.write)
        self.sstp.state = CALL_DISCONNECT_ACK_PENDING
        reactor.callLater(5, self.sstp.transport.loseConnection)


class SSTPProtocol(Protocol):
    state = SERVER_CALL_DISCONNECTED
    sstpPacketLength = 0
    receiveBuffer = ''
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
            self.factory.remotePool.unregister(self.pppd.remote)
        if self.helloTimer.active():
            self.helloTimer.cancel()


    def httpDataReceived(self, data):
        self.receiveBuffer += data
        if "\r\n\r\n" not in self.receiveBuffer:
            return
        requestLine = self.receiveBuffer.split('\r\n')[0]
        self.receiveBuffer = ''
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
        self.receiveBuffer += data
        while len(self.receiveBuffer) >= 4:
            # Check version.
            if self.receiveBuffer[0] != '\x10':
                logging.warn('Unsupported SSTP version.')
                self.transport.loseConnection()
                return
            # Get length if necessary.
            if not self.sstpPacketLength:
                self.sstpPacketLength = parseLength(self.receiveBuffer[2:4])
            if len(self.receiveBuffer) < self.sstpPacketLength:
                return
            packet = self.receiveBuffer[:self.sstpPacketLength]
            self.receiveBuffer = self.receiveBuffer[self.sstpPacketLength:]
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
        logging.log(VERBOSE, hexdump(data))
        if self.pppd is None:
            print('pppd is None.')
            return
        self.pppd.writeFrame(data)


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
        if self.state in (CALL_ABORT_TIMEOUT_PENDING, CALL_ABORT_PENDING,
                CALL_DISCONNECT_ACK_PENDING, CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        if self.state != SERVER_CONNECT_REQUEST_PENDING:
            logging.warn('Not in the state.')
            self.transport.loseConnection()
            return
        if protocolId != SSTP_ENCAPSULATED_PROTOCOL_PPP:
            logging.warn('Unsupported encapsulated protocol.')
            nak = SSTPControlPacket(SSTP_MSG_CALL_CONNECT_NAK)
            nak.attributes = [(SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID,
                    ATTRIB_STATUS_VALUE_NOT_SUPPORTED)]
            self.addRetryCounterOrAbrot()
            return
        self.nonce = os.urandom(32)
        ack = SSTPControlPacket(SSTP_MSG_CALL_CONNECT_ACK)
        # 3 bytes reserved + 1 byte hash bitmap (SHA-1 only) + nonce.
        ack.attributes = [(SSTP_ATTRIB_CRYPTO_BINDING_REQ,
                '\x00\x00\x00' + '\x03' + self.nonce)]
        ack.writeTo(self.transport.write)
        self.pppd = PPPDProtocol()
        self.pppd.sstp = self
        self.pppd.remote = self.factory.remotePool.apply()
        if self.pppd.remote is None:
            logging.warn('IP address pool is full. '
                    'Cannot accpet new connection.')
            self.abort()
        addressArgument = '%s:%s' % (self.factory.local, self.pppd.remote)
        reactor.spawnProcess(self.pppd, self.factory.pppd,
                args=['local', 'file', self.factory.pppdConfigFile,
                    '115200', addressArgument], usePTY=True)
        self.state = SERVER_CALL_CONNECTED_PENDING


    def sstpMsgCallConnectedReceived(self, hashType, nonce, certHash, macHash):
        if self.state in (CALL_ABORT_TIMEOUT_PENDING, CALL_ABORT_PENDING,
                CALL_DISCONNECT_ACK_PENDING, CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        if self.state != SERVER_CALL_CONNECTED_PENDING:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)
        if nonce != self.nonce:
            logging.warn('Received wrong nonce.')
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return
        self.nonce = None
        # TODO: check certHash and macHash
        logging.log(VERBOSE, "Received cert hash: %s", certHash.encode('hex'))
        logging.log(VERBOSE, "Received MAC hash: %s", macHash.encode('hex'))
        logging.log(VERBOSE, "Hash type: %s", hex(ord(hashType)))
        self.state = SERVER_CALL_CONNECTED
        logging.info('Connection established.')


    def sstpMsgCallAbort(self, status=None):
        if self.state in (CALL_ABORT_TIMEOUT_PENDING,
                CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        logging.warn("Call abort.")
        if self.state == CALL_ABORT_PENDING:
            reactor.callLater(1, self.transport.loseConnection)
            return
        self.state = CALL_ABORT_IN_PROGRESS_2
        msg = SSTPControlPacket(SSTP_MSG_CALL_ABORT)
        msg.writeTo(self.transport.write)
        self.state = CALL_ABORT_PENDING
        reactor.callLater(1, self.transport.loseConnection)


    def sstpMsgCallDisconnect(self, status=None):
        if self.state in (CALL_ABORT_TIMEOUT_PENDING, CALL_ABORT_PENDING,
                CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        logging.info('Received call disconnect request.')
        self.state = CALL_DISCONNECT_IN_PROGRESS_2
        ack = SSTPControlPacket(SSTP_MSG_CALL_DISCONNECT_ACK)
        ack.writeTo(self.transport.write)
        self.state = CALL_DISCONNECT_TIMEOUT_PENDING
        reactor.callLater(1, self.transport.loseConnection)


    def sstpMsgCallDisconnectAck(self):
        if self.state == CALL_DISCONNECT_ACK_PENDING:
            self.transport.loseConnection()
        elif self.state in (CALL_ABORT_PENDING, CALL_ABORT_TIMEOUT_PENDING,
                CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)


    def sstpMsgEchoRequest(self):
        if self.state == SERVER_CALL_CONNECTED:
            response = SSTPControlPacket(SSTP_MSG_ECHO_RESPONSE)
            response.writeTo(self.transport.write)
        elif self.state in (CALL_ABORT_TIMEOUT_PENDING, CALL_ABORT_PENDING,
                CALL_DISCONNECT_ACK_PENDING, CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)


    def sstpMsgEchoResponse(self):
        if self.state == SERVER_CALL_CONNECTED:
            self.helloTimer = reactor.callLater(60, self.helloTimerExpired)
        elif self.state in (CALL_ABORT_TIMEOUT_PENDING, CALL_ABORT_PENDING,
                CALL_DISCONNECT_ACK_PENDING, CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)


    def helloTimerExpired(self, close=False):
        if self.state == SERVER_CALL_DISCONNECTED:
            self.transport.loseConnection()  # TODO: follow HTTP
        elif close:
            logging.warn('Ping time out.')
            self.abort(ATTRIB_STATUS_NEGOTIATION_TIMEOUT)
        else:
            logging.info('Send echo request.')
            echo = SSTPControlPacket(SSTP_MSG_ECHO_REQUEST)
            echo.writeTo(self.transport.write)
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
        msg.writeTo(self.transport.write)
        self.state = CALL_ABORT_PENDING
        reactor.callLater(3, self.transport.loseConnection)


class SSTPProtocolFactory(Factory):
    protocol = SSTPProtocol

    def __init__(self, pppd, pppdConfigFile, local, remotePool):
        self.pppd = pppd
        self.pppdConfigFile = pppdConfigFile
        self.local = local
        self.remotePool = remotePool

