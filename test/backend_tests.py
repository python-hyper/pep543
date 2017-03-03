# -*- coding: utf-8 -*-
"""
A module containing a collection of tests that all backends should be able to
pass. Tests for a specific backend can be written by importing all classes from
this file and setting their class-scoped BACKEND variable to the appropriate
backend.
"""
import pep543


def handshake_buffers(client, server, hostname=None):
    """
    Do a handshake in memory, getting back two buffer objects.
    """
    client_buffer = client.wrap_buffers(hostname)
    server_buffer = server.wrap_buffers()

    client_complete = server_complete = False

    while not (client_complete and server_complete):
        while not client_complete:
            try:
                client_buffer.do_handshake()
            except (pep543.WantWriteError, pep543.WantReadError):
                break
            else:
                client_complete = True

        client_bytes = client_buffer.peek_outgoing(8192)
        if client_bytes:
            server_buffer.receive_from_network(client_bytes)
            client_buffer.consume_outgoing(len(client_bytes))

        while not server_complete:
            try:
                server_buffer.do_handshake()
            except (pep543.WantWriteError, pep543.WantReadError):
                break
            else:
                server_complete = True

        server_bytes = server_buffer.peek_outgoing(8192)
        if server_bytes:
            client_buffer.receive_from_network(server_bytes)
            server_buffer.consume_outgoing(len(server_bytes))

    return client_buffer, server_buffer


class SimpleNegotiation(object):
    """
    These tests do simple TLS negotiation using various configurations.
    """
    BACKEND = None

    def test_no_validation(self, server_cert):
        """
        A Server and Client context that both have their validation settings
        disabled and otherwise use the default configuration can handshake.
        """
        cert = self.BACKEND.certificate.from_file(server_cert['cert'])
        key = self.BACKEND.private_key.from_file(server_cert['key'])

        client_config = pep543.TLSConfiguration(validate_certificates=False)
        server_config = pep543.TLSConfiguration(
            validate_certificates=False,
            certificate_chain=((cert,), key),
        )
        client_context = self.BACKEND.client_context(client_config)
        server_context = self.BACKEND.server_context(server_config)

        client, server = handshake_buffers(client_context, server_context)
        client.write(b'hello world!')
        server.receive_from_network(client.peek_outgoing(8192))
        assert server.read(12) == b'hello world!'
