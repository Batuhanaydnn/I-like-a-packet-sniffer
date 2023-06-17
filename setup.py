from setuptools import setup, find_packages

setup(
    name='I like a packet sniffer',
    version='0.0.1',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'command1=I-like-a-sniffer.main:start_sniffer'
        ]
    },
    install_requires=[
        'scapy',
        'unittest',
        'requests'
    ],
)