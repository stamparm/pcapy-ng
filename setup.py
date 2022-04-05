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

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name=PACKAGE_NAME,
      version="1.0.8",
      url="https://github.com/stamparm/pcapy-ng/",
      author="Miroslav Stampar",
      author_email="miroslav@sqlmap.org",
      maintainer="Miroslav Stampar",
      maintainer_email="miroslav@sqlmap.org",
      platforms=["Unix", "Windows"],
      description="Python pcap extension",
      long_description=read('README'),
      license="Apache",
      ext_modules=[Extension(
          name="pcapy",
          sources=sources,
          define_macros=macros,
          include_dirs=include_dirs,
          library_dirs=library_dirs,
          libraries=libraries)],
      #scripts=['tests/pcapytests.py', 'tests/96pings.pcap'],
      data_files=[
          (os.path.join('share', 'doc', PACKAGE_NAME), ['README', 'LICENSE', 'pcapy.html']),
          (os.path.join('share', 'doc', PACKAGE_NAME, 'tests'), glob.glob('tests/*'))]
      )
