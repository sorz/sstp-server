#!/usr/bin/env python2
from __future__ import print_function
import sys
from setuptools import setup, Extension

from sstpd import __version__ as version


if sys.version_info > (3, ):
    print("""\nthis version of sstp-server is for Python 2.7,
please install v0.5 or above for Python 3.""", file=sys.stderr)
    sys.exit(1)

with open('README.rst') as readme:
    long_description = readme.read()

fcsmodule = Extension('sstpd.codec', sources=['sstpd/codecmodule.c'])

setup(
    name='sstp-server',
    version=version,
    description='Secure Socket Tunneling Protocol (SSTP) VPN server.',
    author='Shell Chen',
    author_email='me@sorz.org',
    url='https://github.com/sorz/sstp-server',
    packages=['sstpd'],
    ext_modules = [fcsmodule],
    entry_points="""
    [console_scripts]
    sstpd = sstpd:run
    """,
    install_requires=[
        'twisted', 'service_identity', 'argparse', 'ipaddress'
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2 :: Only',
        'Topic :: Internet',
        'Topic :: Internet :: Proxy Servers',
        'License :: OSI Approved :: MIT License'
    ],
    long_description=long_description,
    python_requires='==2.7.*'
)

