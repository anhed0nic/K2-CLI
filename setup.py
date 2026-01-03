from setuptools import setup, find_packages

setup(
    name="khao2",
    version="1.0.0",
    description="Forensics stegananalysis platform - Every single bit.",
    packages=find_packages(),
    install_requires=[
        "click>=8.0.0",
        "requests>=2.28.0",
    ],
    entry_points={
        "console_scripts": [
            "k2=khao2.presentation.cli:cli",
        ],
    },
    python_requires=">=3.7",
)
