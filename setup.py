import sys
import setuptools
import distutils.core

import pyzor

try:
    # These automatically run 2to3 and modules and scripts while installing,
    # when ran under Python 3
    from distutils.command.build_py import build_py_2to3 as build_py
    from distutils.command.build_scripts import \
        build_scripts_2to3 as build_scripts
except ImportError:
    from distutils.command.build_py import build_py
    from distutils.command.build_scripts import build_scripts

long_description = """
Pyzor is spam-blocking networked system that uses spam signatures
to identify them.
"""

classifiers = ["Operating System :: POSIX",
               "Operating System :: Microsoft :: Windows",

               "Environment :: Console",
               "Environment :: No Input/Output (Daemon)",

               "Programming Language :: Python",
               "Programming Language :: Python :: 2.6",
               "Programming Language :: Python :: 3",

               "Intended Audience :: System Administrators",

               "Topic :: Communications :: Email",
               "Topic :: Communications :: Email :: Filters",

               "Development Status :: 5 - Production/Stable",

               "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
]

distutils.core.setup(name='pyzor',
                     version=pyzor.__version__,
                     description='networked spam-signature detection',
                     long_description=long_description,
                     author='Frank J. Tobin',
                     author_email='ftobin@neverending.org',
                     license='GPL',
                     platforms='POSIX',
                     keywords='spam',
                     url='http://www.pyzor.org/',
                     scripts=['scripts/pyzor', 'scripts/pyzord',
                              'scripts/pyzor-migrate'],
                     packages=['pyzor',
                               'pyzor.engines',
                               'pyzor.hacks'],
                     classifiers=classifiers,
                     test_suite="tests.suite",
                     cmdclass={'build_py': build_py,
                               'build_scripts': build_scripts,
                     },
)
