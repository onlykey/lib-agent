#!/usr/bin/env python
from setuptools import setup

setup(
    name='onlykey-agent',
    version='1.1.12',
    description='Using OnlyKey as hardware SSH/GPG agent',
    author='CryptoTrust',
    author_email='admin@crp.to',
    url='http://github.com/trustcrypto/onlykey-agent',
    scripts=['onlykey_agent.py'],
    install_requires=[
        'lib-agent>=1.0.3',
        'onlykey>=1.2.6'
    ],
    platforms=['POSIX'],
    classifiers=[
        'Environment :: Console',
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking',
        'Topic :: Communications',
        'Topic :: Security',
        'Topic :: Utilities',
    ],
    entry_points={'console_scripts': [
        'onlykey-agent = onlykey_agent:ssh_agent',
        'onlykey-gpg = onlykey_agent:gpg_tool',
        'onlykey-gpg-agent = onlykey_agent:gpg_agent',
    ]},
)
