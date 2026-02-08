## What is Pcapy-NG? ##

[![Build status](https://ci.appveyor.com/api/projects/status/pi4bqe4kgubgr37x?svg=true)](https://ci.appveyor.com/project/CoreSecurity/pcapy)

Pcapy-NG is a Python extension module that enables software written in
Python to access the routines from the pcap packet capture library. It is
a replacement of [Pcapy](https://github.com/helpsystems/pcapy), which is not
maintained any more and stopped working altogether on Python3.10 
([Issue](https://github.com/helpsystems/pcapy/issues/70)).

From libpcap's documentation: "Libpcap is a system-independent
interface for user-level packet capture. Libpcap provides a portable
framework for low-level network monitoring. Applications include
network statistics collection, security monitoring, network debugging,
etc."

## Setup ##

### Quick start ###

Grab the latest stable release, unpack it and run `python setup.py
install` from the directory where you placed it. Isn't that easy?

### [Documentation](https://raw.githack.com/stamparm/pcapy-ng/master/pcapy.html) ###

### Requirements ###

 * A Python interpreter. Versions 2.1.3 and newer are known to work.
 * A C++ compiler. GCC G++ 2.95, as well as Microsoft Visual Studio
   6.0, are known to work.
 * Libpcap 0.7.2 or newer. Windows user are best to check WinPcap 3.0
   or newer.

### Compiling the source and installing ###

As this extension is written in C++ it needs to be compiled for the
host system before it can be accessed from Python. Fortunately this
process has been made easy by the setup.py script. In order to compile
and install the source execute the following command from the
directory where the pcapy's distribution has been unpacked: 'python
setup.py install'. This will install the extension into the default
Python's modules path; note that you might need special permissions to
write there. For more information on what commands and options are
available from setup.py, run `python setup.py --help-commands`.

For Windows, you will need to setup `WPDPACK_BASE` envrionment variable 
to a location where you unziped [WinPcap Developer's Pack](https://www.winpcap.org/devel.htm)


This extension has been tested under Linux and Windows systems
and is known to work there, but it ought to work out-of-the-box on any
system where Python and libpcap are available.

## Licensing ##

This software is provided under under the Apache Software License.
See the accompanying LICENSE file for more information.

## Contact Us ##

Whether you want to report a bug, send a patch or give some
suggestions on this package, drop a few lines at
`miroslav@sqlmap.org`.
