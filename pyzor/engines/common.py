"""Common library shared by different engines."""

import sys
import datetime

from collections import namedtuple

__all__ = ["DBHandle", "DatabaseError", "Record", "BaseEngine"]

DBHandle = namedtuple("DBHandle", ["single_threaded", "multi_threaded",
                                   "multi_processing", "prefork"])


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


class BaseEngine(object):
    """Base class for Pyzor engines."""
    absolute_source = True
    handles_one_step = False

    def __iter__(self):
        """Iterate over all keys"""
        raise NotImplementedError()

    def iteritems(self):
        """Iterate over pairs of (key, record)."""
        raise NotImplementedError()

    def items(self):
        """Return a list of (key, record)."""
        raise NotImplementedError()

    def __getitem__(self, key):
        """Get the record for this corresponding key."""
        raise NotImplementedError()

    def __setitem__(self, key, value):
        """Set the record for this corresponding key. 'value' should be a
        instance of the ``Record`` class.
        """
        raise NotImplementedError()

    def __delitem__(self, key):
        """Remove the corresponding record from the database."""
        raise NotImplementedError()

    def report(self, keys):
        """Report the corresponding key as spam, incrementing the report count.

        Engines that implement don't implement this method should have
        handles_one_step set to False.
        """
        raise NotImplementedError()

    def whitelist(self, keys):
        """Report the corresponding key as ham, incrementing the whitelist
        count.

        Engines that implement don't implement this method should have
        handles_one_step set to False.
        """

        raise NotImplementedError()

    @classmethod
    def get_prefork_connections(cls, fn, mode, max_age=None):
        """Yields an unlimited number of partial functions that return a new
        engine instance, suitable for using toghether with the Pre-Fork server.
        """
        raise NotImplementedError()
