from setuptools import setup, find_packages

setup(
    name="line-client",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "httpx[http2]>=0.24.0",
    ],
    extras_require={
        "thrift": [
            "rsa>=4.9",
            "pycryptodome>=3.18.0",
            "cryptography>=41.0.0",
            "xxhash>=3.0.0",
        ],
    },
    python_requires=">=3.10",
)
