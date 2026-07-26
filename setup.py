#!/usr/bin/env python3
import os
import sys
import subprocess
from setuptools import setup, find_packages

with open(os.path.join(os.path.dirname(__file__), "noxpwn", "__init__.py")) as f:
    for line in f:
        if line.startswith("__version__"):
            version = line.split("=")[1].strip().strip('"').strip("'")
            break
    else:
        version = "1.0.0"

setup(
    name="noxpwn",
    version=version,
    description="noxpwn - Automated Bug Bounty & Pentesting Tool",
    author="noxpwn",
    packages=find_packages(),
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "noxpwn=noxpwn.__main__:main",
        ],
    },
    install_requires=[],
)
