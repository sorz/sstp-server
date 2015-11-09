#!/usr/bin/env python2
from subprocess import Popen
import socket
import time
import ssl


CERT = 'tests/self-signed.pem'
ARGS = ['sstpd', '-c', CERT, '-p', '4433', '-v', '5',
        '--pppd', 'tests/pppd.py']

CERT_HASH = (b'\x9f\xf0\xa8\x8c\xa0\x9c\x00\x6e\x0f\xb0\x22\x2e\xfa\xb6\x5f'
             b'\x4c\xf3\xf5\xb2\x15\xfb\xd2\x6b\x83\x26\x72\x6d\xc6\x88\x12'
             b'\x61\x15')
LCP1_DE = (b'\xff\x03\xc0\x21\x04\x00\x00\x07\x0d\x03\x06')
IP1_DE = (b'\x80\x21\x02\x02\x00\x0a\x03\x06\x0a\x0a\x20\x01')

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


def _sstp_handshake(conn):
    # SSTP_MSG_CALL_CONNECT_REQUEST
    f = conn.makefile('rwb')
    conn.write(b"\x10\x01\x00\x0e\x00\x01\x00\x01\x00\x01\x00\x06\x00\x01")
    time.sleep(0.1)

    # SSTP_MSG_CALL_CONNECT_ACK
    assert f.read(4) == b'\x10\x01\x00\x30'  # ver, C, len
    assert f.read(4) == b'\x00\x02\x00\x01'  # type, num attr
    assert f.read(4) == b'\x00\x04\x00\x28'  # attr 1
    assert f.read(4) == b'\x00\x00\x00\x03'  # proto bitmask
    nonce = f.read(32)
    assert len(nonce) == 32
    f.close()
    return nonce


def _ppp_lcp_test(conn):
    f = conn.makefile('rwb')

    assert f.read(4) == b'\x10\x00\x00\x0f'
    assert f.read(len(LCP1_DE)) == LCP1_DE
    assert f.read(4) == b'\x10\x00\x00\x0f'
    assert f.read(len(LCP1_DE)) == LCP1_DE

    f.write(b'\x10\x00\x00\x0f')
    f.write(LCP1_DE)
    f.write(b'\x10\x00\x00\x0f')
    f.write(LCP1_DE)
    f.flush()

    # Drop echos
    #f.read((4 + len(LCP1_DE)) * 2)

    f.close()


def _ppp_ip_test(conn):
    f = conn.makefile('rwb')
    assert f.read(4) == b'\x10\x00\x00\x10'
    assert f.read(len(IP1_DE)) == IP1_DE

    f.write(b'\x10\x00\x00\x10')
    f.write(IP1_DE)
    f.flush()

    assert f.read(4) == b'\x10\x00\x00\x10'
    assert f.read(len(IP1_DE)) == IP1_DE


def _sstp_connected(conn, nonce):
    f = conn.makefile('rwb')

    # SSTP_MSG_CALL_CONNECTED
    f.write(b'\x10\x01\x00\x70\x00\x04')  # ver, C, len, type
    f.write(b'\x00\x01\x00\x03\x00\x68')  # attr
    f.write(b'\x00\x00\x00\x02')  # hash bitmap
    f.write(nonce)
    f.write(CERT_HASH)
    f.write(b'\x00' * 32)  # MAC
    f.flush()
    f.close()


def test_connect():
    conn = _ssl_connect()
    time.sleep(0.1)
    _http_handshake(conn)
    time.sleep(0.1)
    nonce = _sstp_handshake(conn)
    time.sleep(0.1)
    _ppp_lcp_test(conn)
    time.sleep(0.1)
    _sstp_connected(conn, nonce)
    time.sleep(0.1)
    _ppp_ip_test(conn)


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

