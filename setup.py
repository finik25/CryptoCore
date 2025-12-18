from setuptools import setup, find_packages

setup(
    name="cryptocore",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "pycryptodome>=3.20.0",
    ],
    entry_points={
        "console_scripts": [
            "cryptocore=cryptocore.cli:main",
            "cryptocore-nist=cryptocore.utils.nist_tool:main",
        ],
    },
    python_requires=">=3.8",
    author="finik25",
    description="A minimalist cryptographic provider",
    keywords="crypto encryption decryption aes",
)
