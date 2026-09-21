"""
Complete a group of HTTP/2 requests in a single write.

A race condition in a server is easiest to reach when several requests become
processable at the very same moment. Sending them one after another leaves
milliseconds between them, which is usually enough for the server to finish the
first before the rest arrive.

Marking flows as members of a race group asks mitmproxy to send each request as
usual but hold back its final byte, until every member is ready. All the members
are then completed in one write, so the server sees them together.

Every member must travel over the same upstream HTTP/2 connection, so they need the
same destination. Anything that cannot be honoured -- a non-HTTP/2 upstream, a group
larger than the connection allows, a request with trailers or one being streamed --
is logged and sent normally.
"""

import logging

from mitmproxy import http

GROUP_SIZE = 3


class RaceGroup:
    def __init__(self) -> None:
        self.members = 0

    def request(self, flow: http.HTTPFlow) -> None:
        if not flow.request.path.startswith("/redeem"):
            return
        if self.members >= GROUP_SIZE:
            return  # the group is full; let the rest through normally
        self.members += 1
        flow.request.race_group = http.RaceGroupSpec("redeem", GROUP_SIZE)
        logging.info(f"race group 'redeem': member {self.members}/{GROUP_SIZE}")


addons = [RaceGroup()]
