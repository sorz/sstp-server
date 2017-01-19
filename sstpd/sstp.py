from __future__ import absolute_import
import os
import struct
import logging
from twisted.internet.protocol import Factory, Protocol
from twisted.internet import reactor

from . import __version__
from .constants import *
from .packets import SSTPDataPacket, SSTPControlPacket
from .utils import hexdump
from .ppp import PPPDProtocol
from .proxy_protocol import parse_pp_header, PPException, PPNoEnoughData


HTTP_REQUEST_BUFFER_SIZE = 10 * 1024

def parseLength(s):
    s = chr(ord(s[0]) & 0x0f) + s[1]  # Ignore R
    return struct.unpack('!H', s)[0]


class SSTPProtocol(Protocol):

    def __init__(self):
        self.state = SERVER_CALL_DISCONNECTED
        self.sstpPacketLength = 0
        self.receiveBuffer = ''
        self.nonce = None
        self.pppd = None
        self.retryCounter = 0
        self.helloTimer = reactor.callLater(60, self.helloTimerExpired)
        self.proxyProtocolPassed = False
        self.remoteHost = None


    def connectionMade(self):
        self.proxyProtocolPassed = not self.factory.proxyProtocol
        peer = self.transport.getPeer()
        if hasattr(peer, 'host'):
            self.remoteHost = str(peer.host)


    def dataReceived(self, data):
        if self.state == SERVER_CALL_DISCONNECTED:
            if self.proxyProtocolPassed:
                self.httpDataReceived(data)
            else:
                self.proxyProtoclDataReceived(data)
        else:
            self.sstpDataReceived(data)


    def connectionLost(self, reason):
        logging.debug('Connection finished.')
        if self.pppd is not None and self.pppd.transport is not None:
            self.pppd.transport.loseConnection()
            if self.factory.remotePool is not None:
                self.factory.remotePool.unregister(self.pppd.remote)
        if self.helloTimer.active():
            self.helloTimer.cancel()


    def proxyProtoclDataReceived(self, data):
        self.receiveBuffer += data
        try:
            src, dest, self.receiveBuffer = parse_pp_header(self.receiveBuffer)
        except PPNoEnoughData:
            pass
        except PPException as e:
            logging.warning('PROXY PROTOCOL parsing error: %s', str(e))
            self.transport.loseConnection()
        else:
            logging.debug('PROXY PROTOCOL header parsed: src %s, dest %s', src, dest)
            self.remoteHost = src[0]
            self.proxyProtocolPassed = True
            if self.receiveBuffer:
                self.dataReceived('')


    def httpDataReceived(self, data):
        def close(*args):
            logging.warning(*args)
            self.transport.loseConnection()

        self.receiveBuffer += data
        if "\r\n\r\n" not in self.receiveBuffer:
            if len(self.receiveBuffer) > HTTP_REQUEST_BUFFER_SIZE:
                close('Request too large, may not a valid HTTP request.')
            return
        requestLine = self.receiveBuffer.split('\r\n')[0]
        self.receiveBuffer = ''
        try:
            method, uri, version = requestLine.split()
        except ValueError:
            return close('Not a valid HTTP request.')
        if method != "SSTP_DUPLEX_POST" or version != "HTTP/1.1":
            return close('Unexpected HTTP method (%s) and/or version (%s).',
                         method, version)
        self.transport.write('HTTP/1.1 200 OK\r\n'
                'Content-Length: 18446744073709551615\r\n'
                'Server: SSTP-Server/%s\r\n\r\n' % __version__)
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
        if __debug__:
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
        if self.factory.remotePool:
            self.pppd.remote = self.factory.remotePool.apply()
            if self.pppd.remote is None:
                logging.warn('IP address pool is full. '
                             'Cannot accpet new connection.')
                self.abort()
        else:
            self.pppd.remote = ''

        addressArgument = '%s:%s' % (self.factory.local, self.pppd.remote)
        args = ['local', 'file', self.factory.pppdConfigFile,
                '115200', addressArgument]
        if self.remoteHost is not None:
            args += ['remotenumber', self.remoteHost]
        reactor.spawnProcess(self.pppd, self.factory.pppd, args=args, usePTY=True)
        self.transport.registerProducer(self.pppd, True)
        self.pppd.resumeProducing()
        self.state = SERVER_CALL_CONNECTED_PENDING


    def sstpMsgCallConnectedReceived(self, hashType, nonce, certHash, macHash):
        if self.state in (CALL_ABORT_TIMEOUT_PENDING, CALL_ABORT_PENDING,
                CALL_DISCONNECT_ACK_PENDING, CALL_DISCONNECT_TIMEOUT_PENDING):
            return
        if self.state != SERVER_CALL_CONNECTED_PENDING:
            self.abort(ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED)
        # TODO: check certHash and macHash
        logging.debug("Received cert hash: %s", certHash.encode('hex'))
        logging.debug("Received MAC hash: %s", macHash.encode('hex'))
        logging.debug("Hash type: %s", hex(ord(hashType)))

        if nonce != self.nonce:
            logging.warn('Received wrong nonce.')
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return
        self.nonce = None

        if self.factory.certHash is not None \
                and certHash not in self.factory.certHash:
            logging.warning("Certificate hash mismatch between server's "
                            "and client's. Reject this connection.")
            self.abort(ATTRIB_STATUS_INVALID_FRAME_RECEIVED)
            return

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


    def writePPPControlFrame(self, frame):
        logging.debug('PPP control frame received (%s bytes).' % len(frame))
        logging.log(VERBOSE, hexdump(frame))
        if self.state == SERVER_CALL_CONNECTED_PENDING or \
                self.state == SERVER_CALL_CONNECTED:
            packet = SSTPDataPacket(frame)
            packet.writeTo(self.transport.write)


    def writePPPDataFrame(self, frame):
        if __debug__:
            logging.debug('PPP data frame received (%s bytes).' % len(frame))
            logging.log(VERBOSE, hexdump(frame))
        if self.state == SERVER_CALL_CONNECTED:
            packet = SSTPDataPacket(frame)
            packet.writeTo(self.transport.write)


    def pppStoped(self):
        if (self.state != SERVER_CONNECT_REQUEST_PENDING and
                self.state != SERVER_CALL_CONNECTED_PENDING and
                self.state != SERVER_CALL_CONNECTED):
            self.transport.loseConnection()
            return
        self.state = CALL_DISCONNECT_IN_PROGRESS_1
        msg = SSTPControlPacket(SSTP_MSG_CALL_DISCONNECT)
        msg.attributes = [(SSTP_ATTRIB_NO_ERROR, ATTRIB_STATUS_NO_ERROR)]
        msg.writeTo(self.transport.write)
        self.state = CALL_DISCONNECT_ACK_PENDING
        reactor.callLater(5, self.transport.loseConnection)


class SSTPProtocolFactory(Factory):
    protocol = SSTPProtocol

    def __init__(self, config, remotePool, certHash=None):
        self.pppd = config.pppd
        self.pppdConfigFile = config.pppd_config
        self.local = config.local
        self.proxyProtocol = config.proxy_protocol
        self.remotePool = remotePool
        self.certHash = certHash

