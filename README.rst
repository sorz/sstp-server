sstp-server
============
|PyPI version|
|Build Status|

A Secure Socket Tunneling Protocol (SSTP) server implemented by Python/Twisted.


Requirements
------------

* Python 2.7
* pppd

Install
-------

Install from PyPI:
::

    # pip install sstp-server


Install from GitHub:
::

    # pip install git+https://github.com/sorz/sstp-server.git


Usage
-----

Create pppd configure file `/etc/ppp/options.sstpd`,

A example:
::

        name sstpd
        require-mschap-v2
        nologfd
        nodefaultroute
        ms-dns 8.8.8.8
        ms-dns 8.8.4.4

Start server:
::

    # sstpd -p 443 -c cert.pem --local 10.0.0.1 --remote 10.0.0.0/24

Known Issues
------------

Not yet implement *Crypto Binding*. It may be vulnerable by MITM attack.

License
-------
The MIT License (MIT)

Copyright (c) 2014-2017 Shell Chen


.. |PyPI version| image:: https://img.shields.io/pypi/v/sstp-server.svg?style=flat
        :target: https://pypi.python.org/pypi/sstp-server

.. |Build Status| image:: https://travis-ci.org/sorz/sstp-server.svg?branch=master
        :target: https://travis-ci.org/sorz/sstp-server
