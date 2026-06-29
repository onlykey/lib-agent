#!/usr/bin/env python
import os

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))
try:
    with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
        long_description = f.read()
except IOError:
    long_description = 'Using OnlyKey as hardware SSH/GPG agent'

setup(
    name='onlykey-agent',
    version='1.1.16',
    description='Using OnlyKey as hardware SSH/GPG agent',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='CryptoTrust',
    author_email='admin@crp.to',
    url='http://github.com/trustcrypto/onlykey-agent',
    project_urls={
        'Homepage': 'https://github.com/trustcrypto/onlykey-agent',
        'Documentation': 'https://docs.onlykey.io',
        'Source': 'https://github.com/trustcrypto/onlykey-agent',
    },
    scripts=['onlykey_agent.py'],
    install_requires=[
        'lib-agent>=1.0.6',
        'onlykey>=1.2.8'
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
