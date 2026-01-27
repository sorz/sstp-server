#!/usr/bin/env python3
from setuptools import setup, Extension

fcsmodule = Extension('sstpd.codec', sources=['sstpd/codecmodule.c'])

setup(
    ext_modules=[fcsmodule],
)

