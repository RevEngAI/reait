#!/usr/bin/env python3
from setuptools import setup, find_packages


with open("requirements.txt") as fd:
    required = fd.read().splitlines()

with open("README.md", encoding="utf-8") as fd:
    long_description = fd.read()


setup(
    name="reait",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/RevEng-AI/reait",
    author="James Patrick-Evans",
    author_email="james@reveng.ai",
    platforms="Cross Platform",
    packages=find_packages(
        where="src",
        exclude=[
            "tests",
        ],
    ),
    package_dir={
        "": "src",
    },
    classifiers=[
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ],
    install_requires=required,
)
