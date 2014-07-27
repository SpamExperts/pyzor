"""A collection of utilities that facilitate working with Pyzor accounts.

Note that accounts are not necessary (on the client or server), as an
"anonymous" account always exists."""

import time
import hashlib

import pyzor


def sign_msg(hashed_key, timestamp, msg, hash_=hashlib.sha1):
    """Converts the key, timestamp (epoch seconds), and msg into a digest.

    lower(H(H(M) + ':' T + ':' + K))
    M is message
    T is integer epoch timestamp
    K is hashed_key
    H is the hash function (currently SHA1)
    """
    msg = msg.as_string().strip().encode("utf8")
    digest = hash_()
    digest.update(hash_(msg).digest())
    digest.update((":%d:%s" % (timestamp, hashed_key)).encode("utf8"))
    return digest.hexdigest().lower()


def hash_key(key, user, hash_=hashlib.sha1):
    """Returns the hash key for this username and password.

    lower(H(U + ':' + lower(K)))
    K is key (hex string)
    U is username
    H is the hash function (currently SHA1)
    """
    result = ("%s:%s" % (user, key.lower())).encode("utf8")
    return hash_(result).hexdigest().lower()


def verify_signature(msg, user_key):
    """Verify that the provided message is correctly signed.

    The message must have "User", "Time", and "Sig" headers.

    If the signature is valid, then the function returns normally.
    If the signature is not valid, then a pyzor.SignatureError() exception
    is raised."""
    timestamp = int(msg["Time"])
    user = msg["User"]
    provided_signature = msg["Sig"]
    # Check that this signature is not too old.
    if abs(time.time() - timestamp) > pyzor.MAX_TIMESTAMP_DIFFERENCE:
        raise pyzor.SignatureError("Timestamp not within allowed range.")
    # Calculate what the correct signature is.
    hashed_user_key = hash_key(user_key, user)
    # The signature is not part of the message that is signed.
    del msg["Sig"]
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
    return salt, key

AnonymousAccount = Account(pyzor.anonymous_user, None, "")
