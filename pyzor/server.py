"""Networked spam-signature detection server.

The server receives the request in the form of a RFC5321 message, and
responds with another RFC5321 message.  Neither of these messages has a
body - all of the data is encapsulated in the headers.

The response headers will always include a "Code" header, which is a
HTTP-style response code, and a "Diag" header, which is a human-readable
message explaining the response code (typically this will be "OK").

Both the request and response headers always include a "PV" header, which
indicates the protocol version that is being used (in a major.minor format).
Both the requestion and response headers also always include a "Thread",
which uniquely identifies the request (this is a requirement of using UDP).
Responses to requests may arrive in any order, but the "Thread" header of
a response will always match the "Thread" header of the appropriate request.

Authenticated requests must also have "User", "Time" (timestamp), and "Sig"
(signature) headers.
"""
import os
import sys
import time
import errno
import socket
import signal
import logging
import threading
import traceback
import email.message

try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer

import pyzor.config
import pyzor.account
import pyzor.engines.common

import pyzor.hacks.py26


pyzor.hacks.py26.hack_all()


def _eintr_retry(func, *args):
    """restart a system call interrupted by EINTR"""
    while True:
        try:
            return func(*args)
        except OSError as e:
            if e.args[0] != errno.EINTR:
                raise


class Server(SocketServer.UDPServer):
    """The pyzord server.  Handles incoming UDP connections in a single
    thread and single process."""
    max_packet_size = 8192
    time_diff_allowance = 180

    def __init__(self, address, database, passwd_fn, access_fn,
                 forwarder=None):
        if ":" in address[0]:
            Server.address_family = socket.AF_INET6
        else:
            Server.address_family = socket.AF_INET
        self.log = logging.getLogger("pyzord")
        self.usage_log = logging.getLogger("pyzord-usage")
        self.database = database
        self.one_step = getattr(self.database, "handles_one_step", False)

        # Handle configuration files
        self.passwd_fn = passwd_fn
        self.access_fn = access_fn
        self.accounts = {}
        self.acl = {}
        self.load_config()

        self.forwarder = forwarder

        self.log.debug("Listening on %s", address)
        SocketServer.UDPServer.__init__(self, address, RequestHandler,
                                        bind_and_activate=False)
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except (AttributeError, socket.error) as e:
            self.log.debug("Unable to set IPV6_V6ONLY to false %s", e)
        self.server_bind()
        self.server_activate()

        # Finally, set signals
        signal.signal(signal.SIGUSR1, self.reload_handler)
        signal.signal(signal.SIGTERM, self.shutdown_handler)

    def load_config(self):
        """Reads the configuration files and loads the accounts and ACLs."""
        self.accounts = pyzor.config.load_passwd_file(self.passwd_fn)
        self.acl = pyzor.config.load_access_file(self.access_fn, self.accounts)

    def shutdown_handler(self, *args, **kwargs):
        """Handler for the SIGTERM signal. This should be used to kill the
        daemon and ensure proper clean-up.
        """
        self.log.info("SIGTERM received. Shutting down.")
        t = threading.Thread(target=self.shutdown)
        t.start()

    def reload_handler(self, *args, **kwargs):
        """Handler for the SIGUSR1 signal. This should be used to reload
        the configuration files.
        """
        self.log.info("SIGUSR1 received. Reloading configuration.")
        t = threading.Thread(target=self.load_config)
        t.start()

    def handle_error(self, request, client_address):
        self.log.error("Error while processing request from: %s",
                       client_address, exc_info=True)


class PreForkServer(Server):
    """The same as Server, but prefork itself when starting the self, by
    forking a number of child-processes.

    The parent process will then wait for all his child process to complete.
    """
    def __init__(self, address, database, passwd_fn, access_fn, prefork=4):
        """The same as Server.__init__ but requires a list of databases
        instead of a single database connection.
        """
        self.pids = None
        Server.__init__(self, address, database, passwd_fn, access_fn)
        self._prefork = prefork

    def serve_forever(self, poll_interval=0.5):
        """Fork the current process and wait for all children to finish."""
        pids = []
        for dummy in xrange(self._prefork):
            database = self.database.next()
            pid = os.fork()
            if not pid:
                # Create the database in the child process, to prevent issues
                self.database = database()
                Server.serve_forever(self, poll_interval=poll_interval)
                os._exit(0)
            else:
                pids.append(pid)
        self.pids = pids
        for pid in self.pids:
            _eintr_retry(os.waitpid, pid, 0)

    def shutdown(self):
        """If this is the parent process send the TERM signal to all children,
        else call the super method.
        """
        for pid in self.pids or ():
            os.kill(pid, signal.SIGTERM)
        if self.pids is None:
            Server.shutdown(self)

    def load_config(self):
        """If this is the parent process send the USR1 signal to all children,
        else call the super method.
        """
        for pid in self.pids or ():
            os.kill(pid, signal.SIGUSR1)
        if self.pids is None:
            Server.load_config(self)


class ThreadingServer(SocketServer.ThreadingMixIn, Server):
    """A threaded version of the pyzord server.  Each connection is served
    in a new thread.  This may not be suitable for all database types."""
    pass


class BoundedThreadingServer(ThreadingServer):
    """Same as ThreadingServer but this also accepts a limited number of
    concurrent threads.
    """

    def __init__(self, address, database, passwd_fn, access_fn, max_threads,
                 forwarding_server=None):
        ThreadingServer.__init__(self, address, database, passwd_fn, access_fn,
                                 forwarder=forwarding_server)
        self.semaphore = threading.Semaphore(max_threads)

    def process_request(self, request, client_address):
        self.semaphore.acquire()
        ThreadingServer.process_request(self, request, client_address)

    def process_request_thread(self, request, client_address):
        ThreadingServer.process_request_thread(self, request, client_address)
        self.semaphore.release()


class ProcessServer(SocketServer.ForkingMixIn, Server):
    """A multi-processing version of the pyzord server.  Each connection is
    served in a new process. This may not be suitable for all database types.
    """

    def __init__(self, address, database, passwd_fn, access_fn,
                 max_children=40, forwarding_server=None):
        ProcessServer.max_children = max_children
        Server.__init__(self, address, database, passwd_fn, access_fn,
                        forwarder=forwarding_server)


class RequestHandler(SocketServer.DatagramRequestHandler):
    """Handle a single pyzord request."""

    def __init__(self, *args, **kwargs):
        self.response = email.message.Message()
        SocketServer.DatagramRequestHandler.__init__(self, *args, **kwargs)

    def handle(self):
        """Handle a pyzord operation, cleanly handling any errors."""
        self.response["Code"] = "200"
        self.response["Diag"] = "OK"
        self.response["PV"] = "%s" % pyzor.proto_version
        try:
            self._really_handle()
        except NotImplementedError as e:
            self.handle_error(501, "Not implemented: %s" % e)
        except pyzor.UnsupportedVersionError as e:
            self.handle_error(505, "Version Not Supported: %s" % e)
        except pyzor.ProtocolError as e:
            self.handle_error(400, "Bad request: %s" % e)
        except pyzor.SignatureError as e:
            self.handle_error(401, "Unauthorized: Signature Error: %s" % e)
        except pyzor.AuthorizationError as e:
            self.handle_error(403, "Forbidden: %s" % e)
        except Exception as e:
            self.handle_error(500, "Internal Server Error: %s" % e)
            self.server.log.error(traceback.format_exc())
        self.server.log.debug("Sending: %r", self.response.as_string())
        self.wfile.write(self.response.as_string().encode("utf8"))

    def _really_handle(self):
        """handle() without the exception handling."""
        self.server.log.debug("Received: %r", self.packet)

        # Read the request.
        # Old versions of the client sent a double \n after the signature,
        # which screws up the RFC5321 format.  Specifically handle that
        # here - this could be removed in time.
        request = email.message_from_bytes(
            self.rfile.read().replace(b"\n\n", b"\n") + b"\n")

        # Ensure that the response can be paired with the request.
        self.response["Thread"] = request["Thread"]

        # If this is an authenticated request, then check the authentication
        # details.
        user = request["User"] or pyzor.anonymous_user
        if user != pyzor.anonymous_user:
            try:
                pyzor.account.verify_signature(request,
                                               self.server.accounts[user])
            except KeyError:
                raise pyzor.SignatureError("Unknown user.")

        if "PV" not in request:
            raise pyzor.ProtocolError("Protocol Version not specified in "
                                      "request")

        # The protocol version is compatible if the major number is
        # identical (changes in the minor number are unimportant).
        try:
            if int(float(request["PV"])) != int(pyzor.proto_version):
                raise pyzor.UnsupportedVersionError()
        except ValueError:
            self.server.log.warn("Invalid PV: %s", request["PV"])
            raise pyzor.ProtocolError("Invalid Protocol Version")

        # Check that the user has permission to execute the requested
        # operation.
        opcode = request["Op"]
        if opcode not in self.server.acl[user]:
            raise pyzor.AuthorizationError(
                "User is not authorized to request the operation.")
        self.server.log.debug("Got a %s command from %s", opcode,
                              self.client_address[0])
        # Get a handle to the appropriate method to execute this operation.
        try:
            dispatch = self.dispatches[opcode]
        except KeyError:
            raise NotImplementedError("Requested operation is not "
                                      "implemented.")
        # Get the existing record from the database (or a blank one if
        # there is no matching record).
        digests = request.get_all("Op-Digest")

        # Do the requested operation, log what we have done, and return.
        if dispatch and digests:
            dispatch(self, digests)
        self.server.usage_log.info("%s,%s,%s,%r,%s", user,
                                   self.client_address[0], opcode, digests,
                                   self.response["Code"])

    def handle_error(self, code, message):
        """Create an appropriate response for an error."""
        self.server.usage_log.error("%s: %s", code, message)
        self.response.replace_header("Code", "%d" % code)
        self.response.replace_header("Diag", message)

    def handle_pong(self, digests):
        """Handle the 'pong' command.

        This command returns maxint for report counts and 0 whitelist.
        """
        self.server.log.debug("Request pong for %s", digests[0])
        self.response["Count"] = "%d" % sys.maxint
        self.response["WL-Count"] = "%d" % 0

    def handle_check(self, digests):
        """Handle the 'check' command.

        This command returns the spam/ham counts for the specified digest.
        """
        digest = digests[0]
        try:
            record = self.server.database[digest]
        except KeyError:
            record = pyzor.engines.common.Record()
        self.server.log.debug("Request to check digest %s", digest)
        self.response["Count"] = "%d" % record.r_count
        self.response["WL-Count"] = "%d" % record.wl_count

    def handle_report(self, digests):
        """Handle the 'report' command in a single step.

        This command increases the spam count for the specified digests."""
        self.server.log.debug("Request to report digests %s", digests)
        if self.server.one_step:
            self.server.database.report(digests)
        else:
            for digest in digests:
                try:
                    record = self.server.database[digest]
                except KeyError:
                    record = pyzor.engines.common.Record()
                record.r_increment()
                self.server.database[digest] = record
        if self.server.forwarder:
            for digest in digests:
                self.server.forwarder.queue_forward_request(digest)

    def handle_whitelist(self, digests):
        """Handle the 'whitelist' command in a single step.

        This command increases the ham count for the specified digests."""
        self.server.log.debug("Request to whitelist digests %s", digests)
        if self.server.one_step:
            self.server.database.whitelist(digests)
        else:
            for digest in digests:
                try:
                    record = self.server.database[digest]
                except KeyError:
                    record = pyzor.engines.common.Record()
                record.wl_increment()
                self.server.database[digest] = record
        if self.server.forwarder:
            for digest in digests:
                self.server.forwarder.queue_forward_request(digest, True)

    def handle_info(self, digests):
        """Handle the 'info' command.

        This command returns diagnostic data about a digest (timestamps for
        when the digest was first/last seen as spam/ham, and spam/ham
        counts).
        """
        digest = digests[0]
        try:
            record = self.server.database[digest]
        except KeyError:
            record = pyzor.engines.common.Record()
        self.server.log.debug("Request for information about digest %s",
                              digest)

        def time_output(time_obj):
            """Convert a datetime object to a POSIX timestamp.

            If the object is None, then return 0.
            """
            if not time_obj:
                return 0
            return time.mktime(time_obj.timetuple())

        self.response["Entered"] = "%d" % time_output(record.r_entered)
        self.response["Updated"] = "%d" % time_output(record.r_updated)
        self.response["WL-Entered"] = "%d" % time_output(record.wl_entered)
        self.response["WL-Updated"] = "%d" % time_output(record.wl_updated)
        self.response["Count"] = "%d" % record.r_count
        self.response["WL-Count"] = "%d" % record.wl_count

    dispatches = {
        'ping': None,
        'pong': handle_pong,
        'info': handle_info,
        'check': handle_check,
        'report': handle_report,
        'whitelist': handle_whitelist,
    }
