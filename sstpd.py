#!/usr/bin/env python2
import logging
from twisted.internet.endpoints import SSL4ServerEndpoint
from twisted.internet import reactor, ssl

from protocols import SSTPProtocolFactory


def main():
    logging.basicConfig(level=logging.INFO,
            format='%(asctime)s %(levelname)-s: %(message)s')
    certData = open('test.sorz.org.pem').read()
    certificate = ssl.PrivateCertificate.loadPEM(certData)
    reactor.listenSSL(10728, SSTPProtocolFactory(), certificate.options())
    logging.info('Server started.')
    reactor.run()


if __name__ == '__main__':
    main()
