from setuptools import setup, find_packages

setup(
    name="splat",
    version="1.0",
    install_requires=[
        "appdirs==1.4.3",
        "docopt==0.6.2",
        "hvac==0.2.17",
        "packaging==16.8",
        "pyparsing==2.2.0",
        "six==1.10.0",
        "systemd-python==234",
        "arrow==0.10.0",
    ],
    python_requires=">=3.6",
    packages=find_packages(),
    scripts=['bin/splat'],
)
