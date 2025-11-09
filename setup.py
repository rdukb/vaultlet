from setuptools import setup, find_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()

setup(
    name="vaultlet",
    version="0.1.0",
    description="Lightweight cross-platform password generator with encrypted local history",
    long_description=(here / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="Rajesh Dorairajan",
    author_email="rajesh@tekzon.com",
    license="MIT",
    url="https://github.com/rajeshd/vaultlet",
    packages=find_packages(),
    install_requires=["cryptography>=43", "keyring>=25"],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "vaultlet = app.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
