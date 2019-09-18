#!/usr/bin/env python3

from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()
    setup(
        name='crackq_client',
        author='Daniel Turner',
        version='0.0.1',
        packages=['crackq_client'],
        description="RESTful client for CrackQ",
        long_description=long_description,
        long_description_content_type="text/markdown",
        url="https://github.com/f0cker/crackq_client",
        install_requires=[
            'idna>=2.8',
            'requests>=2.22.0',
            ],
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: POSIX",
            "Operating System :: MacOS",
            ],
        entry_points={
            'console_scripts': [
                'crackq = crackq_client.client:main',
            ]
            },
        )
