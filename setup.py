import sys
import os
import glob
from setuptools import setup, Extension

PACKAGE_NAME = 'pcapy-ng'

# You might want to change these to reflect your specific configuration
include_dirs = []
library_dirs = []
libraries = []

if sys.platform == 'win32':
    if os.environ.get('WPDPACK_BASE'):
        wpdpack = os.environ['WPDPACK_BASE']
        include_dirs.append(os.path.join(wpdpack, 'Include'))
        if sys.maxsize > 2**32:  # x64 Python interpreter
            library_dirs.append(os.path.join(wpdpack, 'Lib', 'x64'))
        else:  # x86 Python interpreter
            library_dirs.append(os.path.join(wpdpack, 'Lib'))
    else:
        # WinPcap include files
        include_dirs.append(r'c:\wpdpack\Include')
        # WinPcap library files
        if sys.maxsize > 2**32:  # x64 Python interpreter
            library_dirs.append(r'c:\wpdpack\Lib\x64')
        else:  # x86 Python interpreter
            library_dirs.append(r'c:\wpdpack\Lib')
    libraries = ['wpcap', 'packet', 'ws2_32']
else:
    libraries = ['pcap']


# end of user configurable parameters
macros = []
sources = ['pcapdumper.cc',
           'bpfobj.cc',
           'pcapobj.cc',
           'pcap_pkthdr.cc',
           'pcapy.cc'
           ]

if sys.platform == 'win32':
    sources.append(os.path.join('win32', 'dllmain.cc'))
    macros.append(('WIN32', '1'))

def test_data_files():
    # Plain files only: a stale tests/__pycache__ directory (left behind by any earlier test
    # run in the source tree) makes install_data abort with "can't copy ...: not a regular file".
    return sorted(f for f in glob.glob(os.path.join('tests', '*'))
                  if os.path.isfile(f) and not f.endswith(('.pyc', '.pyo')))


def read(fname):
    f = open(os.path.join(os.path.dirname(__file__), fname))
    try:
        return f.read()
    finally:
        f.close()

setup(name=PACKAGE_NAME,
      version="2.0.1",
      url="https://github.com/stamparm/pcapy-ng/",
      project_urls={
          "Source": "https://github.com/stamparm/pcapy-ng/",
          "Issues": "https://github.com/stamparm/pcapy-ng/issues",
          "Changelog": "https://github.com/stamparm/pcapy-ng/blob/master/ChangeLog",
      },
      author="Miroslav Stampar",
      author_email="miroslav@sqlmap.org",
      maintainer="Miroslav Stampar",
      maintainer_email="miroslav@sqlmap.org",
      platforms=["Linux", "macOS", "Windows"],
      description="Maintained libpcap binding for Python (Pcapy-compatible) with optional in-C packet classification",
      long_description=read('README.md'),
      long_description_content_type="text/markdown",
      keywords=["pcap", "libpcap", "sniffer", "packet capture", "network", "pcapy", "npcap"],
      license="Apache-2.0",
      # 2.7 and 3.8+ are supported and tested; 3.0-3.7 are not.
      python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*, !=3.6.*, !=3.7.*",
      classifiers=[
          "Development Status :: 5 - Production/Stable",
          "Intended Audience :: Developers",
          "Intended Audience :: System Administrators",
          "Intended Audience :: Telecommunications Industry",
          # NOTE: no "License ::" classifier on purpose -- superseded by the SPDX
          # expression in license= above (setuptools >= 77 deprecates the classifiers).
          "Operating System :: MacOS :: MacOS X",
          "Operating System :: Microsoft :: Windows",
          "Operating System :: POSIX :: Linux",
          "Operating System :: POSIX :: BSD",
          "Programming Language :: C++",
          "Programming Language :: Python :: 2",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.8",
          "Programming Language :: Python :: 3.9",
          "Programming Language :: Python :: 3.10",
          "Programming Language :: Python :: 3.11",
          "Programming Language :: Python :: 3.12",
          "Programming Language :: Python :: 3.13",
          "Programming Language :: Python :: 3.14",
          "Programming Language :: Python :: Implementation :: CPython",
          "Topic :: Security",
          "Topic :: System :: Networking :: Monitoring",
      ],
      ext_modules=[Extension(
          name="pcapy",
          sources=sources,
          define_macros=macros,
          include_dirs=include_dirs,
          library_dirs=library_dirs,
          libraries=libraries)],
      #scripts=['tests/pcapytests.py', 'tests/96pings.pcap'],
      data_files=[
          (os.path.join('share', 'doc', PACKAGE_NAME), ['README', 'README.md', 'LICENSE', 'pcapy.html']),
          (os.path.join('share', 'doc', PACKAGE_NAME, 'tests'), test_data_files())]
      )
