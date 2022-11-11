import setuptools

with open("README.md", "r") as f:
    long_description = f.read()

setuptools.setup(
        name="rea",
        version="0.0.1",
        scripts=['rea'],
        author="James Patrick-Evans",
        description="A python utility to interface with RevEng.AI REST API",
        long_description=long_description,
        long_description_content_type="text/markdown",
        url="https://github.com/RevEng-AI/rea",
        packages=setuptools.find_packages(),
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: GPLv3",
            "Operating System :: OS Independent"
            ],
        )

