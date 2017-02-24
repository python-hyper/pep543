# -*- coding: utf-8 -*-
import codecs

from setuptools import setup

packages = [
    'pep543',
]

with codecs.open('README.rst', encoding='utf-8') as f:
    readme = f.read()

setup(
    name='pep543',
    version='0.0.1',
    description='A Unified TLS API for Python',
    long_description=readme,
    author='Cory Benfield',
    author_email='cory@lukasa.co.uk',
    url='https://python-hyper.org',
    packages=packages,
    package_data={'': ['LICENSE', 'README.rst']},
    package_dir={'pep543': 'pep543'},
    include_package_data=True,
    license='MIT License',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
    ],
)
