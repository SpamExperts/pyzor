"""A collection of utilities that facilitate working with Pyzor accounts.

Note that accounts are not necessary (on the client or server), as an
"anonymous" account always exists."""

import os
import time
import hashlib
import logging
import collections

import pyzor

# This is the maximum time between a client signing a Pyzor request and the
# server checking the signature.
MAX_TIMESTAMP_DIFFERENCE = 300 # seconds

def sign_msg(hashed_key, timestamp, msg, hash=hashlib.sha1):
    """Converts the key, timestamp (epoch seconds), and msg into a digest.

    lower(H(H(M) + ':' T + ':' + K))
    M is message
    T is decimal epoch timestamp
    K is hashed_key
    H is the hash function (currently SHA1)
    """
    return hash("%s:%d:%s" % (hash(str(msg)).digest(), timestamp,
                              hashed_key)).hexdigest().lower()

def hash_key(key, user, hash=hashlib.sha1):
    """Returns the hash key for this username and password.

    lower(H(U + ':' + lower(K)))
    K is key (hex string)
    U is username
    H is the hash function (currently SHA1)
    """
    return hash("%s:%s" % (user, key.lower())).hexdigest().lower()

def verify_signature(msg, user_key):
    """Verify that the provided message is correctly signed.

    The message must have "User", "Time", and "Sig" headers.

    If the signature is valid, then the function returns normally.
    If the signature is not valid, then a pyzor.SignatureError() exception
    is raised."""
    timestamp = int(request["Time"])
    user = request["User"]
    provided_signature = request["Sig"]
    # Check that this signature is not too old.
    if abs(time.time() - timestamp) > MAX_TIMESTAMP_DIFFERENCE:
        raise SignatureError("Timestamp not within allowed range.")
    # Calculate what the correct signature is.
    hashed_user_key = hash_key(user_key, user)
    # The signature is not part of the message that is signed.
    del request["Sig"]
    correct_signature = sign_msg(hashed_user_key, timestamp, msg)
    if correct_signature != provided_signature:
        raise pyzor.SignatureError("Invalid signature.")

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
