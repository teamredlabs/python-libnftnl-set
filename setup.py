"""The setup.py script."""

import os

from setuptools import setup, Extension
from setuptools.command.build_py import build_py


class libnftnl_build_py(build_py):

    def run(self):
        build_py.run(self)
        dest = os.path.join(
            self.build_lib,
            'libnftnlset-stubs',
            '__init__.pyi',
        )
        self.mkpath(os.path.dirname(dest))
        self.copy_file('libnftnlset.pyi', dest)


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
      ext_modules=[Extension(name='libnftnlset',
                             sources=['libnftnlset.c'],
                             libraries=['nftnl', 'mnl'])],
      cmdclass={'build_py': libnftnl_build_py},
      packages=['libnftnlset-stubs'],
      zip_safe=False)
