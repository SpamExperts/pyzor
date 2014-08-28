"""Manage the forwarder process."""

import logging
import threading

try:
    import Queue
except ImportError:
    import queue as Queue


class Forwarder(object):
    """Forwards digest to remote pyzor servers"""

    def __init__(self, forwarding_client, remote_servers,
                 max_queue_size=10000):
        """
        forward_client: a pyzor.client.Client instance to use as
                        forwarding client
        remote_servers: a list of (hostname,port) tuples where digests should
                        be forwarded to
        max_queue_size: max amount of queued digests
        """
        self.log = logging.getLogger("pyzord")
        self.forwarding_client = forwarding_client
        self.forward_queue = Queue.Queue(max_queue_size)
        self.remote_servers = remote_servers

    def _forward_loop(self):
        """read forwarding requests from the queue"""
        while True:
            try:
                digest, whitelist = self.forward_queue.get(block=True,
                                                           timeout=2)
            except Queue.Empty:
                # If the forwarding client has been deleted we should
                # end the thread
                if self.forwarding_client is None:
                    return
                else:
                    continue

            for server in self.remote_servers:
                try:
                    if whitelist:
                        self.forwarding_client.whitelist(digest, server)
                    else:
                        self.forwarding_client.report(digest, server)
                except Exception as ex:
                    self.log.warn('Forwarding digest %s to %s failed: %s',
                                  digest, server, ex)

    def queue_forward_request(self, digest, whitelist=False):
        """If forwarding is enabled, insert a digest into the forwarding queue
        if whitelist is True, the digest will be forwarded as whitelist request
        if the queue is full, the digest is dropped
        """
        if self.forwarding_client is None:  # forwarding has been disabled
            return

        try:
            self.forward_queue.put_nowait((digest, whitelist),)
        except Queue.Full:
            pass

    def start_forwarding(self):
        """start the forwarding thread"""
        threading.Thread(target=self._forward_loop).start()

    def stop_forwarding(self):
        """disable forwarding and tell the forwarding thread to end itself"""
        self.forwarding_client = None
