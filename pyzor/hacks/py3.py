"""Hacks for python2-3 compatibility."""

import sys


def _reload(module):
    """Reload the module.

    This is handled differently according to the
    python version. This even varies across Python3
    versions
    """
    if sys.version_info[0] == 2:
        # Built-in method
        return reload(module)
    elif sys.version_info[0] == 3 and sys.version_info[1] <= 3:
        import imp

        return imp.reload(module)
    else:
        import importlib

        return importlib.reload(module)
