#!/usr/bin/env python3
import sys
import logging
import argparse
from configparser import SafeConfigParser, NoSectionError
import ssl
import asyncio
try:
    import uvloop
except ImportError:
    uvloop = None

from . import __doc__
from .sstp import SSTPProtocolFactory
from .address import IPPool


def _get_args():
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
            metavar='PEM-CERT',
            help='Path of PEM-format certificate.')
    parser.add_argument('-k', '--pem-key',
            metavar='PEM-KEY',
            help='Path of private key file if separated from the '
                 'certificate file.')
    parser.add_argument('-n', '--no-ssl',
            action='store_true',
            help='Use plain HTTP instead of HTTPS. '
                 'Useful when running behind a reverse proxy.')
    parser.add_argument('--proxy-protocol',
            action='store_true',
            help='Enable PROXY PROTOCOL, imply --no-ssl')
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
    args.no_ssl = args.proxy_protocol or args.no_ssl
    return args


def _load_cert(cert_path, key_path=None):
    if not cert_path:
        logging.error('argument -c/--pem-cert is required')
        sys.exit(2)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        context.load_cert_chain(certfile=cert_path,
                                keyfile=key_path if key_path else cert_path)
    except IOError as e:
        logging.critical(e)
        logging.critical('Cannot read certificate.')
        sys.exit(2)
    return context


def main():
    args = _get_args()
    logging.basicConfig(level=args.log_level,
            format='%(asctime)s %(levelname)-s: %(message)s')
    logging.addLevelName(5, 'VERBOSE')

    if args.remote:
        ippool = IPPool(args.remote)
        ippool.register(args.local)
    else:
        ippool = None

    if args.no_ssl:
        ssl_ctx = None
        cert_hash = None
        logging.info('Running without SSL.')
    else:
        ssl_ctx = _load_cert(args.pem_cert, args.pem_key)
        if args.ciphers:
            ssl_ctx.set_ciphers(args.ciphers)
        #sha1 = cert.digest('sha1').replace(':', '').decode('hex')
        #sha256 = cert.digest('sha256').replace(':', '').decode('hex')
        # TODO: set cert hash on cert_hash[sha1, sha256]
        cert_hash = None
    on_unix_socket = args.listen.startswith('/')

    if uvloop is None:
        logging.info('Running without uvloop')
    else:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        logging.info('Using uvloop')
    loop = asyncio.get_event_loop()
    factory = SSTPProtocolFactory(args,
                                  remote_pool=ippool,
                                  cert_hash=cert_hash)
    if on_unix_socket:
        coro = loop.create_unix_server(factory,
                                       args.listen,
                                       ssl=ssl_ctx)
    else:
        coro = loop.create_server(factory,
                                  args.listen,
                                  args.listen_port,
                                  ssl=ssl_ctx)
    server = loop.run_until_complete(coro)

    if args.proxy_protocol:
        logging.info('PROXY PROTOCOL is activated.')
    if on_unix_socket:
        logging.info('Listening on %s...', args.listen)
    else:
        logging.info('Listening on %s:%s...', args.listen, args.listen_port)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logging.info('Exit by interrupt')
    finally:
        loop.close()

if __name__ == '__main__':
    main()

