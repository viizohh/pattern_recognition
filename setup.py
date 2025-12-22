from setuptools import setup, find_packages

setup(
    name="net-watch",
    version="0.1.0",
    description="Command-line network monitoring tool with human-readable security analysis",
    author="Network Security Tools",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "click>=8.1.0",
        "colorama>=0.4.6",
        "tabulate>=0.9.0",
        "python-dateutil>=2.8.2",
    ],
    entry_points={
        "console_scripts": [
            "hound=net_watch.cli:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
    ],
)
