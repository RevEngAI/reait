import setuptools

with open("README.md", "r") as f:
    long_description = f.read()

setuptools.setup(
        name="reait",
        version="0.0.16",
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
                'tqdm', 'argparse', 'requests', 'rich', 'tomli', 'pandas', 'numpy', "scipy"
            ],
    )

