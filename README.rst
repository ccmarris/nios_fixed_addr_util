=======================
NIOS Fixed Address Util
=======================

| Version: 0.1.0
| Author: Chris Marrison
| Email: chris@infoblox.com

Description
-----------

Provides a python class to assist with managing fixed addresses and 
whether they are in use. The class can be used to either build a report 
or can directly update the fixed address objects with an extensible attribute.

Demonstration code is included that enables this to be used as a simple 
script.


Prerequisites
-------------

Python 3.8+


Installing Python
~~~~~~~~~~~~~~~~~

You can install the latest version of Python 3.x by downloading the appropriate
installer for your system from `python.org <https://python.org>`_.

.. note::

  If you are running MacOS Catalina (or later) Python 3 comes pre-installed.
  Previous versions only come with Python 2.x by default and you will therefore
  need to install Python 3 as above or via Homebrew, Ports, etc.

  By default the python command points to Python 2.x, you can check this using 
  the command::

    $ python -V

  To specifically run Python 3, use the command::

    $ python3


.. important::

  Mac users will need the xcode command line utilities installed to use pip3,
  etc. If you need to install these use the command::

    $ xcode-select --install

.. note::

  If you are installing Python on Windows, be sure to check the box to have 
  Python added to your PATH if the installer offers such an option 
  (it's normally off by default).


Modules
~~~~~~~

Non-standard modules:

    - rich (for pretty printing)

Complete list of modules::

  import logging
  import requests
  import argparse
  import configparser
  import time
  import datetime
  from rich import print


Installation
------------

The simplest way to install and maintain the tools is to clone this 
repository::

    % git clone https://github.com/ccmarris/nios_fixed_addr_util


Alternative you can download as a Zip file.


Basic Configuration
-------------------

The script utilise a gm.ini file to specify the Grid Master, API version
and user/password credentials.


gm.ini
~~~~~~~

The *gm.ini* file is used by the scripts to define the details to connect to
to Grid Master. A sample inifile is provided and follows the following 
format::

  [NIOS]
  gm = '192.168.1.10'
  api_version = 'v2.12'
  valid_cert = 'false'
  user = 'admin'
  pass = 'infoblox'


You can use either an IP or hostname for the Grid Master. This inifile 
should be kept in a safe area of your filesystem. 

Use the --config/-c option to override the default ini file.


Usage
-----

The script support -h or --help on the command line to access the options 
available::

  % ./nios_fixed_addr_util.py --help
  usage: nios_fixed_addr_util.py [-h] [-c CONFIG] [-f FILTER] [-u] [-e EA] [-a] [-d]

  NIOS Fixed Address Utility

  options:
    -h, --help            show this help message and exit
    -c CONFIG, --config CONFIG
                          Override ini file
    -f FILTER, --filter FILTER
                          Filter report by type [ all, True, False, Reserved, Unknown ]
    -u, --update          Update fixed address object in NIOS
    -e EA, --ea EA        Name of EA to use (type STRING)
    -a, --auto            Auto create EA if it does not exist
    -d, --debug           Enable debug messages


nios_fixed_addr_util
~~~~~~~~~~~~~~~~~~~~


Examples
--------

Simple Report on Fixed Address:

  % ./nios_fixed_addr_util.py --config gm.ini 

Enable debug::

  % ./nios_fixed_addr_util.py --config gm.ini --debug

Filter report:

  % ./nios_fixed_addr_util.py --config gm.ini --match_use 'False'
  % ./nios_fixed_addr_util.py --config gm.ini --match_use 'True'
  % ./nios_fixed_addr_util.py --config gm.ini --match_use 'Reserved'
  % ./nios_fixed_addr_util.py --config gm.ini --match_use 'Unknown'

Add/update Extensible Attribute on fixed address objects in NIOS:

  % ./nios_fixed_addr_util.py --config gm.ini --update

Use an alternate EA name from default (with auto create):

  % ./nios_fixed_addr_util.py --config gm.ini --update --ea_name 'Lease_status' --auto


License
-------

This project is licensed under the 2-Clause BSD License
- please see LICENSE file for details.


Aknowledgements
---------------

