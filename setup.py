# -*- coding: utf-8 -*-
import setuptools

from reait import __version__

with open("README.md", "r") as f:
    long_description = f.read()

setuptools.setup(
        name="reait",
        version=__version__,
        long_description=long_description,
        long_description_content_type="text/markdown",
        url="https://github.com/RevEng-AI/reait",
        author="James Patrick-Evans",
        packages=setuptools.find_packages(where='src', exclude=['tests']),
        package_dir={"": "src"},
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
            "Operating System :: OS Independent"
            ],
        install_requires=[
                'tqdm', 'argparse', 'requests', 'rich', 'tomli', 'pandas', 'numpy', "scipy", "scikit-learn"
            ],
    )
