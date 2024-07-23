from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="otp-manager",
    version="1.1",
    author="Lorenzo Antonelli",
    description="OTP Manager is a command-line tool for managing and generating One-Time Passwords (OTPs) for various services.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/lorenzoantonelli/otp-manager",
    packages=find_packages(),
    install_requires=["cryptography", "pyotp", "segno"],
    entry_points={
        "console_scripts": [
            "otp-manager=otp_manager.main:main",
        ],
    },
)
