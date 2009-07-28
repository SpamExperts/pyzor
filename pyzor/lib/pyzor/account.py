import os
import logging
import collections

import pyzor

class Account(object):
    def __init__(self, username, salt, key):
        self.username = username
        self.salt = salt
        self.key = key

def key_from_hexstr(s):
    try:
        salt, key = s.split(",")
    except ValueError:
        raise ValueError("Invalid number of parts for key; perhaps you "
                         "forgot the comma at the beginning for the "
                         "salt divider?")
    if salt:
        salt = long(salt, 16)
    else:
        salt = None
    if key:
        key = long(key, 16)
    else:
        key = None
    return salt, key

def load_accounts(filename):
    """Layout of file is: host : port : username : salt,key"""
    accounts = {}
    log = logging.getLogger("pyzor")
    if os.path.exists(filename):
        for lineno, orig_line in enumerate(open(filename)):
            line = orig_line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                host, port, username, key = [x.strip()
                                             for x in line.split(":")]
            except ValueError:
                log.warn("account file: invalid line %d: "
                         "wrong number of parts" % lineno)
                continue
            try:
                port = int(port)
            except ValueError, e:
                log.warn("account file: invalid line %d: %s" % (lineno, e))
            address = (host, port)
            salt, key = key_from_hexstr(key)
            if not salt and not key:
                log.warn("account file: invalid line %d: "
                         "keystuff can't be all None's" % lineno)
                continue
            try:
                accounts[address] = Account(username, salt, key)
            except ValueError, e:
                log.warn("account file: invalid line %d: %s" % (lineno, e))
    else:
        log.warn("No accounts are setup.  All commands will be executed by "
                 "the anonymous user.")
    return accounts

AnonymousAccount = Account(pyzor.anonymous_user, None, 0)
