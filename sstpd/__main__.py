#!/usr/bin/env python2
import sys
import logging
import argparse
from twisted.internet.endpoints import SSL4ServerEndpoint
from twisted.internet import reactor, ssl

from sstp import SSTPProtocolFactory
from address import IPPool


def _getArgs():
    parser = argparse.ArgumentParser(description='A Secure Socket Tunneling '
            'Protocol (SSTP) server.',
            epilog='Author: Sorz <orz@sorz.org>.')
    parser.add_argument('-l', '--listen',
            default='',
            metavar='ADDRESS',
            help='The address to bind to, default to all.')
    parser.add_argument('-p', '--listen-port',
            default=443, type=int,
            metavar='PORT')
    parser.add_argument('-c', '--pem-cert',
            metavar='PEM-FILE',
            help='The path of PEM-format certificate with key.')
    parser.add_argument('-n', '--no-ssl',
            action='store_true',
            help='Use plain HTTP instead of HTTPS. '
                 'Useful when running behind a reverse proxy.')
    parser.add_argument('--pppd',
            default='/usr/sbin/pppd',
            metavar='PPPD-FILE')
    parser.add_argument('--pppd-config',
            default='/etc/ppp/options.sstpd',
            metavar='CONFIG-FILE',
            help='Default to /etc/ppp/options.sstpd')
    parser.add_argument('--local',
            default='192.168.20.1',
            metavar='ADDRESS',
            help="Address of server side on ppp, default to 192.168.20.1")
    parser.add_argument('--remote',
            metavar='NETWORK',
            help="Enable internal IP management. Client's IP will be selected "
                 "from NETWORK (e.g. 192.168.20.0/24).")
    parser.add_argument('--ciphers',
            metavar="CIPHER-LIST",
            help='Custom OpenSSL cipher suite. See ciphers(1).')
    parser.add_argument('-v', '--log-level',
            default=logging.INFO, type=int,
            metavar='LOG-LEVEL',
            help="1 to 50. Default 20, debug 10, verbose 5.")

    return parser.parse_args()


def _load_cert(path):
    if not path:
        logging.error('argument -c/--pem-cert is required')
        sys.exit(2)
    try:
        certData = open(path).read()
    except IOError as e:
        logging.critical(e)
        logging.critical('Cannot read certificate.')
        sys.exit(2)
    return ssl.PrivateCertificate.loadPEM(certData)


def main():
    args = _getArgs()
    logging.basicConfig(level=args.log_level,
            format='%(asctime)s %(levelname)-s: %(message)s')
    logging.addLevelName(5, 'VERBOSE')

    if args.remote:
        ippool = IPPool(args.remote)
        ippool.register(args.local)
    else:
        ippool = None

    if args.no_ssl:
        logging.info('Running without SSL.')
        factory = SSTPProtocolFactory(pppd=args.pppd, pppdConfigFile=args.pppd_config,
                local=args.local, remotePool=ippool, certHash=None)
        reactor.listenTCP(args.listen_port, factory)
    else:
        cert = _load_cert(args.pem_cert)
        sha1 = cert.digest('sha1').replace(':', '').decode('hex')
        sha256 = cert.digest('sha256').replace(':', '').decode('hex')
        cert_options = cert.options()

        if args.ciphers:
            cert_options.getContext().set_cipher_list(args.ciphers)

        factory = SSTPProtocolFactory(pppd=args.pppd, pppdConfigFile=args.pppd_config,
                local=args.local, remotePool=ippool, certHash=[sha1, sha256])
        reactor.listenSSL(args.listen_port, factory,
                cert_options, interface=args.listen)

    logging.info('Listening on %s:%s...' % (args.listen, args.listen_port))
    reactor.run()


if __name__ == '__main__':
    main()
