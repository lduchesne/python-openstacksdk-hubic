from distutils.core import setup

setup(
    name = "openstacksdk-hubic",
    version = "0.1",
    packages = ['hubic'],
    description = "HubiC authentication interface compatible with the Python OpenStack SDK",
    author = "Laurent Duchesne",
    author_email = "l@urent.org",
    url = "https://github.com/lduchesne/python-openstacksdk-hubic",
    classifiers = [
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
