import sys
sys.path.append('lib')
import pyzor
import distutils.core

long_description = """
Pyzor is spam-blocking networked system that uses spam signatures
to identify them.
"""

distutils.core.setup( name = 'pyzor',
                      version = pyzor.__version__,
                      description = 'networked spam-signature detection',
		      long_description = long_description,
                      author = 'Frank J. Tobin',
                      author_email = 'ftobin@users.sourceforge.net',
		      license = 'GPL',
		      platforms = 'POSIX',
		      keywords = 'spam',
                      url = 'http://pyzor.sourceforge.net/',
                      scripts=['scripts/pyzor', 'scripts/pyzord'],
                      package_dir = {'': 'lib'},
                      packages = ['pyzor'],
                      )
