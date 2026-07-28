import os
from setuptools import setup, find_packages

with open(os.path.join(os.path.dirname(__file__), "src", "noxpwn", "__init__.py")) as f:
    for line in f:
        if line.startswith("__version__"):
            version = line.split("=")[1].strip().strip('"').strip("'")
            break
    else:
        version = "1.1.5"

with open(os.path.join(os.path.dirname(__file__), "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="noxpwn",
    version=version,
    description="Automated Bug Bounty & Pentesting Tool (17 phases, 32 tools)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="noxpwn",
    url="https://github.com/Egzozzz/noxpwn",
    project_urls={
        "Bug Tracker": "https://github.com/Egzozzz/noxpwn/issues",
        "Source": "https://github.com/Egzozzz/noxpwn",
    },
    license="MIT",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "noxpwn=noxpwn.__main__:main",
        ],
    },
    install_requires=[],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security :: Penetration Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
    ],
    keywords="bug-bounty, penetration-testing, security, reconnaissance, automation",
)
