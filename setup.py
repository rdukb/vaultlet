from setuptools import setup, find_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()

setup(
    name="vaultlet",
    version="1.0.0",
    description="Local secrets vault with passkey unlock, encrypted backup import/export, and password generation",
    long_description=(here / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="Rajesh Dorairajan",
    author_email="rajesh@tekzon.com",
    license="MIT",
    url="https://github.com/rajeshd/vaultlet",
    packages=find_packages(),
    install_requires=["cryptography>=43", "keyring>=25", "webauthn>=2.7", "argon2-cffi>=23"],
    python_requires=">=3.10",
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
