#!/usr/bin/env python2
import logging
import argparse
from twisted.internet.endpoints import SSL4ServerEndpoint
from twisted.internet import reactor, ssl

from protocols import SSTPProtocolFactory


def _getArgs():
    parser = argparse.ArgumentParser(description='A Secure Socket Tunneling '
            'Protocol (SSTP) server.',
            epilog='Auther: @xierch <orz@sorz.org>.')
    parser.add_argument('-l', '--listen',
            default='',
            metavar='ADDRESS',
            help='The address to bind to, default to all.')
    parser.add_argument('-p', '--listen-port',
            default=443, type=int,
            metavar='PORT')
    parser.add_argument('-c', '--pem-cert',
            required=True,
            metavar='PEM-FILE',
            help='The path of PEM-format certificate with key.')
    parser.add_argument('--pppd',
            default='/usr/sbin/pppd',
            metavar='PPPD-FILE')
    parser.add_argument('--pppd-config',
            default='/etc/ppp/options.sstpd',
            metavar='CONFIG-FILE',
            help='Default to /etc/ppp/options.sstpd')

    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.INFO,
            format='%(asctime)s %(levelname)-s: %(message)s')
    args = _getArgs()
    print(args)

    try:
        certData = open(args.pem_cert).read()
    except IOError as e:
        logging.critical(e)
        logging.critical('Cannot read certificate.')
        return

    certificate = ssl.PrivateCertificate.loadPEM(certData)
    factory = SSTPProtocolFactory(pppd=args.pppd, pppdConfigFile=args.pppd_config)
    reactor.listenSSL(args.listen_port, factory,
            certificate.options(), interface=args.listen)
    logging.info('Listening on %s:%s...' % (args.listen, args.listen_port))
    reactor.run()


if __name__ == '__main__':
    main()
