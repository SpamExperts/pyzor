"""Common library shared by different engines."""

import sys
import datetime

from collections import namedtuple

__all__ = ["DBHandle", "DatabaseError", "Record"]

DBHandle = namedtuple("DBHandle", ["single_threaded", "multi_threaded",
                                   "multi_processing"])


class DatabaseError(Exception):
    pass


class Record(object):
    """Prefix conventions used in this class:
    r = report (spam)
    wl = whitelist
    """
    def __init__(self, r_count=0, wl_count=0, r_entered=None,
                 r_updated=None, wl_entered=None, wl_updated=None):
        self.r_count = r_count
        self.wl_count = wl_count
        self.r_entered = r_entered
        self.r_updated = r_updated
        self.wl_entered = wl_entered
        self.wl_updated = wl_updated

    def wl_increment(self):
        # overflow prevention
        if self.wl_count < sys.maxint:
            self.wl_count += 1
        if self.wl_entered is None:
            self.wl_entered = datetime.datetime.now()
        self.wl_update()

    def r_increment(self):
        # overflow prevention
        if self.r_count < sys.maxint:
            self.r_count += 1
        if self.r_entered is None:
            self.r_entered = datetime.datetime.now()
        self.r_update()

    def r_update(self):
        self.r_updated = datetime.datetime.now()

    def wl_update(self):
        self.wl_updated = datetime.datetime.now()

