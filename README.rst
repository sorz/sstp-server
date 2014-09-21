sstp-server
============

A Secure Socket Tunneling Protocol (SSTP) server implemented by Python/Twisted.


Requirements
============

* Python 2.7
* pppd

Install
=======

::

    # pip install sstp-server

Usage
=====

Create pppd configure file `/etc/ppp/options.sstpd`,

A example:
::

        name sstpd
        require-mschap-v2
        nodefaultroute
        nopcomp
        ms-dns 8.8.8.8
        ms-dns 8.8.4.4

Start server:
::

    # sstpd -p 443 -c cert.pem --local 10.0.0.1 --remote 10.0.0.0/24

Known Issues
============

Not yet implement *Crypto Binding*. It may be vulnerable by MITM attck.

