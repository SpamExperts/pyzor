import sys
import setuptools
import distutils.core

sys.path.insert(0, 'lib')
import pyzor

long_description = """
Pyzor is spam-blocking networked system that uses spam signatures
to identify them.
"""

distutils.core.setup(name='pyzor',
                     version=pyzor.__version__,
                     description='networked spam-signature detection',
                     long_description=long_description,
                     author='Frank J. Tobin',
                     author_email='ftobin@neverending.org',
                     license='GPL',
                     platforms='POSIX',
                     keywords='spam',
                     url='http://pyzor.sourceforge.net/',
                     scripts=['scripts/pyzor', 'scripts/pyzord'],
                     package_dir={'': 'lib'},
                     packages=['pyzor'],
                     test_suite="tests.suite",
                     data_files=[('share/doc/pyzor', ['docs/usage.html'])],
                     )
