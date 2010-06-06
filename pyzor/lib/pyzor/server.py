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

from __future__ import division

import time
import logging
import StringIO
import traceback
import SocketServer
import email.message

import pyzor
import pyzor.account
import pyzor.server_engines

class Server(SocketServer.UDPServer):
    """The pyzord server.  Handles incoming UDP connections in a single
    thread and single process."""
    max_packet_size = 8192
    time_diff_allowance = 180

    def __init__(self, address, database, accounts, acl):
        self.log = logging.getLogger("pyzord")
        self.usage_log = logging.getLogger("pyzord-usage")
        self.database = database
        self.accounts = accounts
        self.acl = acl
        self.log.debug("Listening on %s" % (address,))
        SocketServer.UDPServer.__init__(self, address, RequestHandler)

    def serve_forever(self):
        """Process new connections until the program exits."""
        SocketServer.UDPServer.serve_forever(self)


# pylint: disable-msg=R0901
class ThreadingServer(Server, SocketServer.ThreadingUDPServer):
    """A threaded version of the pyzord server.  Each connection is served
    in a new thread.  This may not be suitable for all database types."""
    pass


class RequestHandler(SocketServer.DatagramRequestHandler):
    """Handle a single pyzord request."""
    def __init__(self, *args, **kwargs):
        self.response = email.message.Message()
        SocketServer.DatagramRequestHandler.__init__(self, *args, **kwargs)

    def handle(self):
        """Handle a pyzord operation, cleanly handling any errors."""
        self.response["Code"] = 200
        self.response["Diag"] = "OK"
        self.response["PV"] = "%s" % pyzor.proto_version
        try:
            self._really_handle()
        except pyzor.UnsupportedVersionError, e:
            self.handle_error(505, "Version Not Supported: %s" % e)
        except NotImplementedError, e:
            self.handle_error(501, "Not implemented: %s" % e)
        except pyzor.ProtocolError, e:
            self.handle_error(400, "Bad request: %s" % e)
        except pyzor.AuthorizationError, e:
            self.handle_error(401, "Unauthorized: %s" % e)
        except pyzor.SignatureError, e:
            self.handle_error(401, "Unauthorized, Signature Error: %s" % e)
        except Exception, e:
            self.handle_error(500, "Internal Server Error: %s" % e)
            trace = StringIO.StringIO()
            traceback.print_exc(file=trace)
            trace.seek(0)
            self.server.log.error(trace.read())
        self.server.log.debug("Sending: %r" % self.response.as_string())
        self.wfile.write(self.response.as_string())

    def _really_handle(self):
        """handle() without the exception handling."""
        self.server.log.debug("Received: %r" % self.packet)

        # Read the request.
        # Old versions of the client sent a double \n after the signature,
        # which screws up the RFC5321 format.  Specifically handle that
        # here - this could be removed in time.
        request = email.message_from_string(
            self.rfile.read().replace("\n\n", "\n") + "\n")

        # If this is an authenticated request, then check the authentication
        # details.
        user = request["User"] or pyzor.anonymous_user
        if user != pyzor.anonymous_user:
            try:
                pyzor.account.verify_signature(request,
                                               self.server.accounts[user])
            except KeyError:
                raise pyzor.SignatureError("Unknown user.")

        # The protocol version is compatible if the major number is
        # identical (changes in the minor number are unimportant).
        if int(float(request["PV"])) != int(pyzor.proto_version):
            raise pyzor.UnsupportedVersionError()

        # Check that the user has permission to execute the requested
        # operation.
        opcode = request["Op"]
        if opcode not in self.server.acl[user]:
            raise pyzor.AuthorizationError(
                "User is not authorized to request the operation.")

        # Ensure that the response can be paired with the request.
        self.response["Thread"] = request["Thread"]
        self.server.log.debug("Got a %s command from %s" %
                              (opcode, self.client_address))
        # Get a handle to the appropriate method to execute this operation.
        try:
            dispatch = self.dispatches[opcode]
        except KeyError:
            raise NotImplementedError("Requested operation is not "
                                      "implemented.")
        # Get the existing record from the database (or a blank one if
        # there is no matching record).
        digest = request["Op-Digest"]
        try:
            record = self.server.database[digest]
        except KeyError:
            record = pyzor.server_engines.Record()
        # Do the requested operation, log what we have done, and return.
        if dispatch:
            dispatch(self, digest, record)
        self.server.usage_log.info("%s,%s,%s,%r,%s" %
                                   (user, self.client_address[0], opcode,
                                    digest, self.response["Code"]))

    def handle_error(self, code, message):
        """Create an appropriate response for an error."""
        self.server.log.error("%s: %s" % (code, message))
        self.response.replace_header("Code", "%d" % code)
        self.response.replace_header("Diag", message)

    def handle_check(self, digest, record):
        """Handle the 'check' command.

        This command returns the spam/ham counts for the specified digest.
        """
        self.server.log.debug("Request to check digest %s" % digest)
        self.response["Count"] = "%d" % record.r_count
        self.response["WL-Count"] = "%d" % record.wl_count

    def handle_report(self, digest, record):
        """Handle the 'report' command.

        This command increases the spam count for the specified digest."""
        self.server.log.debug("Request to report digest %s" % digest)
        # Increase the count, and store the altered record back in the
        # database.
        record.r_increment()
        self.server.database[digest] = record

    def handle_whitelist(self, digest, record):
        """Handle the 'whitelist' command.

        This command increases the ham count for the specified digest."""
        self.server.log.debug("Request to whitelist digest %s" % digest)
        # Increase the count, and store the altered record back in the
        # database.
        record.wl_increment()
        self.server.database[digest] = record

    def handle_info(self, digest, record):
        """Handle the 'info' command.

        This command returns diagnostic data about a digest (timestamps for
        when the digest was first/last seen as spam/ham, and spam/ham
        counts).
        """
        self.server.log.debug("Request for information about digest %s" %
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
        'check' : handle_check,
        'report' : handle_report,
        'ping' : None,
        'info' : handle_info,
        'whitelist' : handle_whitelist,
        }
