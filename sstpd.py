#!/usr/bin/env python2
from twisted.internet.endpoints import SSL4ServerEndpoint
from twisted.internet import reactor, ssl

from protocols import SSTPProtocolFactory


def main():
    certData = open('test.sorz.org.pem').read()
    certificate = ssl.PrivateCertificate.loadPEM(certData)
    reactor.listenSSL(10728, SSTPProtocolFactory(), certificate.options())
    reactor.run()


if __name__ == '__main__':
    main()
