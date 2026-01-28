"""A Secure Socket Tunneling Protocol (SSTP) server.
https://github.com/sorz/sstp-server
"""

__version__ = "0.7.0"


def run() -> None:
    from .__main__ import main

    main()
