#!/usr/bin/env python3
"""
Setup configuration for ARGUS tool.
Enables installation via: pip install . or pipx install .
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="argus",
    version="2.1.0",
    author="OSINT Team",
    description="ARGUS — Adaptive Reconnaissance, Gathering, and Understanding Suite",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/domain-osint-tool",
    py_modules=["argus"],
    entry_points={
        "console_scripts": [
            "argus=argus:main",
        ],
    },
    install_requires=requirements,
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Topic :: Internet",
        "Topic :: System :: Networking",
        "Topic :: System :: Monitoring",
    ],
    keywords="osint reconnaissance recon domain enumeration security",
)
