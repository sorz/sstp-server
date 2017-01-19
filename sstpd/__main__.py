#!/usr/bin/env python2
from __future__ import absolute_import, print_function
import sys
import logging
import argparse
from ConfigParser import SafeConfigParser, NoSectionError
from twisted.internet.endpoints import SSL4ServerEndpoint
from twisted.internet import reactor, ssl

from . import __doc__
from .sstp import SSTPProtocolFactory
from .address import IPPool


def _getArgs():
    conf_parser = argparse.ArgumentParser(
            add_help=False)
    conf_parser.add_argument("-f", "--conf-file",
            help="Specify config file.", metavar="FILE")
    conf_parser.add_argument("-s", "--conf-section",
            help="Specify section name on config file.",
            metavar="SITE", default="DEFAULT")

    args, remaining_argv = conf_parser.parse_known_args()
    defaults = {
            'listen': '',
            'listen_port': 443,
            'pppd': '/usr/sbin/pppd',
            'pppd_config': '/etc/ppp/options.sstpd',
            'local': '192.168.20.1',
            'log_level': logging.INFO
    }
    if args.conf_file:
        config = SafeConfigParser()
        config.read(args.conf_file)
        try:
            defaults.update(dict(config.items(args.conf_section)))
        except NoSectionError as e:
            print('Error: section [%s] not found in config file.' % \
                  args.conf_section, file=sys.stderr)
            sys.exit(1)
            return

    parser = argparse.ArgumentParser(parents=[conf_parser],
            description=__doc__)
    parser.set_defaults(**defaults)
    parser.add_argument('-l', '--listen',
            metavar='ADDRESS',
            help='The address to bind to, default to all. Either IP address '
                 'or a path start with "/" for a UNIX domain socket.')
    parser.add_argument('-p', '--listen-port',
            type=int, metavar='PORT')
    parser.add_argument('-c', '--pem-cert',
            metavar='PEM-FILE',
            help='The path of PEM-format certificate with key.')
    parser.add_argument('-n', '--no-ssl',
            action='store_true',
            help='Use plain HTTP instead of HTTPS. '
                 'Useful when running behind a reverse proxy.')
    parser.add_argument('--proxy-protocol',
            action='store_true',
            help='Enable PROXY PROTOCOL, must use together with --no-ssl')
    parser.add_argument('--pppd',
            metavar='PPPD-FILE')
    parser.add_argument('--pppd-config',
            metavar='CONFIG-FILE',
            help='Default to /etc/ppp/options.sstpd')
    parser.add_argument('--local',
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
            type=int, metavar='LOG-LEVEL',
            help="1 to 50. Default 20, debug 10, verbose 5.")

    args = parser.parse_args()
    args.log_level = int(args.log_level)
    args.listen_port = int(args.listen_port)
    args.proxy_protocol = args.proxy_protocol and args.no_ssl
    return args


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

    on_unix_socket = args.listen.startswith('/')
    if on_unix_socket and not args.no_ssl:
        logging.error('Listen on UNIX doamin socket require --no-ssl.')
        sys.exit(2)

    if args.no_ssl:
        logging.info('Running without SSL.')
        factory = SSTPProtocolFactory(args, remotePool=ippool, certHash=None)
        if on_unix_socket:
            reactor.listenUNIX(args.listen, factory)
        else:
            reactor.listenTCP(args.listen_port, factory, interface=args.listen)
    else:
        cert = _load_cert(args.pem_cert)
        sha1 = cert.digest('sha1').replace(':', '').decode('hex')
        sha256 = cert.digest('sha256').replace(':', '').decode('hex')
        cert_options = cert.options()

        if args.ciphers:
            cert_options.getContext().set_cipher_list(args.ciphers)

        factory = SSTPProtocolFactory(args, remotePool=ippool, certHash=[sha1, sha256])
        reactor.listenSSL(args.listen_port, factory,
                cert_options, interface=args.listen)

    if args.proxy_protocol:
        logging.info('PROXY PROTOCOL is activated.')
    if on_unix_socket:
        logging.info('Listening on %s...', args.listen)
    else:
        logging.info('Listening on %s:%s...', args.listen, args.listen_port)
    reactor.run()


if __name__ == '__main__':
    main()
