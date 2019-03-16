# Copyright (c) 2019 Platform9 systems. All rights reserved

from setuptools import setup, find_packages
from vaultlib import __version__

setup(
    name='vaultlib',
    version=__version__,
    description='Client library for accessing Vault.',
    author='',
    author_email='',
    install_requires=[
        'requests'
    ],
    scripts=[],
    zip_safe=False,
    packages=find_packages()
)
