"""Functions that handle parsing pyzor configuration files."""

import os
import re
import logging
import collections

try:
    from raven.handlers.logging import SentryHandler
    _has_raven = True
except ImportError:
    _has_raven = False

import pyzor.account

_COMMENT_P = re.compile(r"((?<=[^\\])#.*)")


# Configuration files for the Pyzor Server
def load_access_file(access_fn, accounts):
    """Load the ACL from the specified file, if it exists, and return an
    ACL dictionary, where each key is a username and each value is a set
    of allowed permissions (if the permission is not in the set, then it
    is not allowed).

    'accounts' is a dictionary of accounts that exist on the server - only
    the keys are used, which must be the usernames (these are the users
    that are granted permission when the 'all' keyword is used, as
    described below).

    Each line of the file should be in the following format:
        operation : user : allow|deny
    where 'operation' is a space-separated list of pyzor commands or the
    keyword 'all' (meaning all commands), 'username' is a space-separated
    list of usernames or the keyword 'all' (meaning all users) - the
    anonymous user is called "anonymous", and "allow|deny" indicates whether
    or not the specified user(s) may execute the specified operations.

    The file is processed from top to bottom, with the final match for
    user/operation being the value taken.  Every file has the following
    implicit final rule:
        all : all : deny

    If the file does not exist, then the following default is used:
        check report ping info : anonymous : allow
    """
    log = logging.getLogger("pyzord")
    # A defaultdict is safe, because if we get a non-existant user, we get
    # the empty set, which is the same as a deny, which is the final
    # implicit rule.
    acl = collections.defaultdict(set)
    if not os.path.exists(access_fn):
        log.info("Using default ACL: the anonymous user may use the check, "
                 "report, ping and info commands.")
        acl[pyzor.anonymous_user] = set(("check", "report", "ping", "pong",
                                         "info"))
        return acl
    accessf = open(access_fn)
    for line in accessf:
        if not line.strip() or line[0] == "#":
            continue
        try:
            operations, users, allowed = [part.lower().strip()
                                          for part in line.split(":")]
        except ValueError:
            log.warn("Invalid ACL line: %r", line)
            continue
        try:
            allowed = {"allow": True, "deny": False}[allowed]
        except KeyError:
            log.warn("Invalid ACL line: %r", line)
            continue
        if operations == "all":
            operations = ("check", "report", "ping", "pong", "info",
                          "whitelist")
        else:
            operations = [operation.strip()
                          for operation in operations.split()]
        if users == "all":
            users = accounts
        else:
            users = [user.strip() for user in users.split()]
        for user in users:
            if allowed:
                log.debug("Granting %s to %s.", ",".join(operations), user)
                # If these operations are already allowed, this will have
                # no effect.
                acl[user].update(operations)
            else:
                log.debug("Revoking %s from %s.", ",".join(operations), user)
                # If these operations are not allowed yet, this will have
                # no effect.
                acl[user].difference_update(operations)
    accessf.close()
    log.info("ACL: %r", acl)
    return acl


def load_passwd_file(passwd_fn):
    """Load the accounts from the specified file.

    Each line of the file should be in the format:
        username : key

    If the file does not exist, then an empty dictionary is returned;
    otherwise, a dictionary of (username, key) items is returned.
    """
    log = logging.getLogger("pyzord")
    accounts = {}
    if not os.path.exists(passwd_fn):
        log.info("Accounts file does not exist - only the anonymous user "
                 "will be available.")
        return accounts
    passwdf = open(passwd_fn)
    for line in passwdf:
        if not line.strip() or line[0] == "#":
            continue
        try:
            user, key = line.split(":")
        except ValueError:
            log.warn("Invalid accounts line: %r", line)
            continue
        user = user.strip()
        key = key.strip()
        log.debug("Creating an account for %s with key %s.", user, key)
        accounts[user] = key
    passwdf.close()
    # Don't log the keys at 'info' level, just ther usernames.
    log.info("Accounts: %s", ",".join(accounts))
    return accounts


# Configuration files for the Pyzor Client
def load_accounts(filepath):
    """Layout of file is: host : port : username : salt,key"""
    accounts = {}
    log = logging.getLogger("pyzor")
    if os.path.exists(filepath):
        accountsf = open(filepath)
        for lineno, orig_line in enumerate(accountsf):
            line = orig_line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                host, port, username, key = [x.strip()
                                             for x in line.split(":")]
            except ValueError:
                log.warn("account file: invalid line %d: wrong number of "
                         "parts", lineno)
                continue
            try:
                port = int(port)
            except ValueError as ex:
                log.warn("account file: invalid line %d: %s", lineno, ex)
                continue
            address = (host, port)
            try:
                salt, key = pyzor.account.key_from_hexstr(key)
            except ValueError as ex:
                log.warn("account file: invalid line %d: %s", lineno, ex)
                continue
            if not salt and not key:
                log.warn("account file: invalid line %d: keystuff can't be "
                         "all None's", lineno)
                continue
            accounts[address] = pyzor.account.Account(username, salt, key)
        accountsf.close()

    else:
        log.warn("No accounts are setup.  All commands will be executed by "
                 "the anonymous user.")
    return accounts


def load_servers(filepath):
    """Load the servers file."""
    logger = logging.getLogger("pyzor")
    if not os.path.exists(filepath):
        servers = []
    else:
        servers = []
        with open(filepath) as serverf:
            for line in serverf:
                line = line.strip()
                if re.match("[^#][a-zA-Z0-9.-]+:[0-9]+", line):
                    address, port = line.rsplit(":", 1)
                    servers.append((address, int(port)))

    if not servers:
        logger.info("No servers specified, defaulting to public.pyzor.org.")
        servers = [("public.pyzor.org", 24441)]
    return servers


def load_local_whitelist(filepath):
    """Load the local digest skip file."""
    if not os.path.exists(filepath):
        return set()

    whitelist = set()
    with open(filepath) as serverf:
        for line in serverf:
            # Remove any comments
            line = _COMMENT_P.sub("", line).strip()
            if line:
                whitelist.add(line)
    return whitelist


# Common configurations
def setup_logging(log_name, filepath, debug, sentry_dsn=None,
                  sentry_lvl="WARN"):
    """Setup logging according to the specified options. Return the Logger
    object.
    """
    fmt = logging.Formatter('%(asctime)s (%(process)d) %(levelname)s '
                            '%(message)s')

    stream_handler = logging.StreamHandler()

    if debug:
        stream_log_level = logging.DEBUG
        file_log_level = logging.DEBUG
    else:
        stream_log_level = logging.CRITICAL
        file_log_level = logging.INFO

    logger = logging.getLogger(log_name)
    logger.setLevel(file_log_level)

    stream_handler.setLevel(stream_log_level)
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)

    if filepath:
        file_handler = logging.FileHandler(filepath)
        file_handler.setLevel(file_log_level)
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)

    if sentry_dsn and _has_raven:
        sentry_level = getattr(logging, sentry_lvl)
        sentry_handler = SentryHandler(sentry_dsn)
        sentry_handler.setLevel(sentry_level)
        logger.addHandler(sentry_handler)

    return logger


def expand_homefiles(homefiles, category, homedir, config):
    """Set the full file path for these configuration files."""
    for filename in homefiles:
        filepath = config.get(category, filename)
        if not filepath:
            continue
        filepath = os.path.expanduser(filepath)
        if not os.path.isabs(filepath):
            filepath = os.path.join(homedir, filepath)
        config.set(category, filename, filepath)
