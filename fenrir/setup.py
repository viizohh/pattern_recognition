from setuptools import setup, find_packages

setup(
    name="fenrir",
    version="1.0.0",
    description="Fenrir - Network security scanner with AI-powered threat analysis",
    author="Network Security Tools",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "click>=8.1.0",
        "colorama>=0.4.6",
        "tabulate>=0.9.0",
        "python-dateutil>=2.8.2",
        "anthropic>=0.18.0",
    ],
    entry_points={
        "console_scripts": [
            "fenrir=net_watch.cli:main",
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
