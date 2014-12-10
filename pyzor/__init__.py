"""Networked spam-signature detection."""

__author__ = "Frank J. Tobin, ftobin@neverending.org"
__credits__ = "Tony Meyer, Dreas von Donselaar, all the Pyzor contributors."
__version__ = "1.0.0"

import hashlib

proto_name = 'pyzor'
proto_version = 2.1
anonymous_user = 'anonymous'

# We would like to use sha512, but that would mean that all the digests
# changed, so for now, we stick with sha1 (which is the same as the old
# sha module).
sha = hashlib.sha1

# This is the maximum time between a client signing a Pyzor request and the
# server checking the signature.
MAX_TIMESTAMP_DIFFERENCE = 300  # seconds


class CommError(Exception):
    """Something in general went wrong with the transaction."""
    code = 400


class ProtocolError(CommError):
    """Something is wrong with talking the protocol."""
    code = 400


class TimeoutError(CommError):
    """The connection timed out."""
    code = 504


class IncompleteMessageError(ProtocolError):
    """A complete requested was not received."""
    pass


class UnsupportedVersionError(ProtocolError):
    """Client is using an unsupported protocol version."""
    pass


class SignatureError(CommError):
    """Unknown user, signature on msg invalid, or not within allowed time
    range."""
    pass


class AuthorizationError(CommError):
    """The signature was valid, but the user is not permitted to do the
    requested action."""
    pass
