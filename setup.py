# -*- coding: utf8 -*-

from setuptools import setup, find_packages

setup(
    name        = 'minica',
    packages    = find_packages(),
    scripts     = ['minica.py'],
    version     = '0.4',
    description = 'minica - small library and cli tool for managing a certificate authority',
    author      = 'Moritz Möller',
    author_email= 'mm@mxs.de',
    url         = 'https://github.com/mo22/minica'
)
