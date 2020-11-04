"""The setup.py script."""

from distutils.core import setup, Extension

setup(name="python-libnftnl-set",
      version='0.0.1',
      description='Python wrapper for libnftnl set/map operations',
      author='John Lawrence M. Penafiel',
      author_email='jonh@teamredlabs.com',
      license='BSD-2-Clause',
      url='https://github.com/teamredlabs/python-libnftnl-set',
      classifiers=['Development Status :: 4 - Beta',
                   'Environment :: Plugins',
                   'Intended Audience :: Developers',
                   'Intended Audience :: Information Technology',
                   'Intended Audience :: System Administrators',
                   'License :: OSI Approved :: BSD License',
                   'Operating System :: POSIX :: Linux',
                   'Programming Language :: C',
                   'Programming Language :: Python :: 2.7',
                   'Topic :: Communications',
                   'Topic :: Internet :: Log Analysis',
                   'Topic :: System :: Networking :: Monitoring'],
      keywords='libnftnl netfilter nftables',
      ext_modules=[Extension(
          name="libnftnlset",
          sources=["libnftnlset.c"],
          libraries=["nftnl", "mnl"]
      )])
