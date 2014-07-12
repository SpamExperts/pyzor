"""Hacks for Python 2.6"""

__all__ = ["hack_all", "hack_email", "hack_select"]


def hack_all(email=True, select=True):
    """Apply all Python 2.6 patches."""
    if email:
        hack_email()
    if select:
        hack_select()


def hack_email():
    """The python2.6 version of email.message_from_string, doesn't work with
    unicode strings. And in python3 it will only work with a decoded.

    So switch to using only message_from_bytes.
    """
    import email
    if not hasattr(email, "message_from_bytes"):
        email.message_from_bytes = email.message_from_string


def hack_select():
    """The python2.6 version of SocketServer does not handle interrupt calls
    from signals. Patch the select call if necessary.
    """
    import sys
    if sys.version_info[0] == 2 and sys.version_info[1] == 6:
        import select
        import errno

        real_select = select.select

        def _eintr_retry(*args):
            """restart a system call interrupted by EINTR"""
            while True:
                try:
                    return real_select(*args)
                except (OSError, select.error) as ex:
                    if ex.args[0] != errno.EINTR:
                        raise
        select.select = _eintr_retry
