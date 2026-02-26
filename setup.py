"""Hashcatizer — File-to-Hashcat Converter Suite."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="hashcatizer",
    version="1.0.0",
    author="Hashcatizer Contributors",
    description="Convert encrypted files to hashcat-compatible hash format",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/hashcatizer",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "pyhanko>=0.21.0",
        "olefile>=0.46",
        "lxml>=4.9.0",
        "pycryptodome>=3.19.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "hashcatizer=hashcatizer:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
