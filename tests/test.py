#!/usr/bin/env python2
from subprocess import Popen
import socket
import time
import ssl


CERT = 'tests/self-signed.pem'
ARGS = ['sstpd', '-c', CERT, '-p', '4433',
        '--pppd-config', 'tests/options.sstpd']

def _ssl_connect():
    conn = socket.create_connection(('127.0.0.1', 4433))
    conn = ssl.wrap_socket(conn, ca_certs=CERT)
    return conn


def _http_handshake(conn):
    conn.write("SSTP_DUPLEX_POST "
               "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"
               "Content-Length: 18446744073709551615\r\n"
               "Host: 127.0.0.1\r\n"
               "SSTPCORRELATIONID: {3F2504E0-4F89-11D3-9A0C-0305E82C3301}\r\n"
               "\r\n")
    resp = conn.recv(4096)
    assert resp.startswith(b'HTTP/1.1 200 OK')


def test_connect():
    conn = _ssl_connect()
    _http_handshake(conn)
    # TODO: SSTP handshake
    # TODO: PPP handshake


def main():
    process = Popen(ARGS)
    time.sleep(2)
    try:
        test_connect()
    finally:
        time.sleep(1)
        process.terminate()


if __name__ == '__main__':
    main()

