# -*- coding: utf-8 -*-
"""
Internal utilities used by the PEP 543 module to implement specific bits of
functionality.
"""
import time

class _Deadline:
    """
    A class that implements a context manager that can be used to provide
    deadline-based timeouts for socket operations.

    A common problem when writing code that wraps sockets, e.g. with TLS, is
    that the user sees only a single call to send/recv, but this may translate
    to multiple low-level socket operations. It perplexes users when they have
    a timeout set for 30s but what appears to be a single function call takes
    vastly in excess of 30s.

    For this reason, a more useful conception of timeouts with socket ops is
    not actually "timeouts" (e.g. how long should a given operation take), but
    "deadlines" (e.g. when must all operations finish). Happily, we can map the
    two concepts into each other: a user setting a 30s timeout on our wrapped
    socket will be translated into a per-call deadline of 30s. This class
    performs that mapping.
    """
    def __init__(self, total_time):
        self._total_time = total_time

    def remaining_time(self):
        """
        How much time is remaining before the deadline. Put another way: if a
        socket operation is begun now, what is the maximum amount of time we
        should wait for it?
        """
        # Short circuit for blocking sockets or those without timeouts.
        if self._total_time is None:
            return None
        elif self._total_time <= 0:
            return self._total_time

        return time.monotonic() - self._start

    def __enter__(self):
        # Short circuit for blocking sockets or those without timeouts.
        if self._total_time is not None and self._total_time > 0:
            self._start = time.monotonic()

        return self

    def __exit__(self, *args):
        # Nothing needs to be done here.
        pass
