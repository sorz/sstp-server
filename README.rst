sstp-server
============
|PyPI version|
|Build Status|

A Secure Socket Tunneling Protocol (SSTP) server implemented by Python.


Requirements
------------

* Python >= 3.4.4
* pppd

For Python 2.7, use v0.4.x

**Crypto Binding** is supported using *SSTP ppp API* plug-in 
sstp-pppd-plugin.so from
`sstp-client <http://sstp-client.sourceforge.net/>`_.

Install
-------

Install from PyPI:
::

    # pip install sstp-server

Please ensure your pip >= 9.0.1 to get correct version.

Install from GitHub:
::

    # pip install git+https://github.com/sorz/sstp-server.git


Arch Linux user may install
`sstp-server <https://aur.archlinux.org/packages/sstp-server/>`_
package from AUR.

If you share the authentication with services other than SSTP
(for example, a RADIUS server that serve both a SSTP and WiFi
authentication), `crypto binding <https://docs.microsoft.com/en-us/openspecs/
windows_protocols/ms-sstp/89a68310-0b1e-451b-af9c-0c9ce500bb2e>`_
is required to prevent MITM attacks. Crypto binding is enabled
automatically if `sstp-pppd-plugin.so` is avaliable, see
`#37 <https://github.com/sorz/sstp-server/pull/37
#issuecomment-761107420>`_ for instructions.

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

.. code:: bash

    sudo sstpd -p 443 -c cert.pem -k key.pem --local 10.0.0.1 --remote 10.0.0.0/24

Or:

.. code:: bash

    sudo sstpd -f /path/to/sstpd-server.ini -s site1

Known Issues
------------

- High CPU usage, may not suitable for high thougthput applications.

License
-------
The MIT License (MIT)

Copyright (c) 2014-2020 Shell Chen


.. |PyPI version| image:: https://img.shields.io/pypi/v/sstp-server.svg?style=flat
        :target: https://pypi.python.org/pypi/sstp-server

.. |Build Status| image:: https://travis-ci.org/sorz/sstp-server.svg?branch=master
        :target: https://travis-ci.org/sorz/sstp-server

