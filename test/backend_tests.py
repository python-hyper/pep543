# -*- coding: utf-8 -*-
"""
A module containing a collection of tests that all backends should be able to
pass. Tests for a specific backend can be written by importing all classes from
this file and setting their class-scoped BACKEND variable to the appropriate
backend.
"""
import pep543

import pytest


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


def assert_configs_work(backend, client_config, server_config):
    """
    Given a pair of configs (one for the client, and one for the server),
    creates contexts and buffers, performs a handshake, and then sends a bit of
    test data to confirm the connection is up.

    Returns the client and server connection.
    """
    client_context = backend.client_context(client_config)
    server_context = backend.server_context(server_config)

    client, server = handshake_buffers(client_context, server_context)
    client.write(b'hello world!')
    server.receive_from_network(client.peek_outgoing(8192))
    assert server.read(12) == b'hello world!'

    return client, server


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
        assert_configs_work(self.BACKEND, client_config, server_config)

    def test_server_validation(self, server_cert, ca_cert):
        """
        A Server and Client context, where the Client context is set to
        validate the server, and otherwise use the default configuration,
        can handshake.
        """
        cert = self.BACKEND.certificate.from_file(server_cert['cert'])
        key = self.BACKEND.private_key.from_file(server_cert['key'])
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(trust_store=trust_store)
        server_config = pep543.TLSConfiguration(
            validate_certificates=False,
            certificate_chain=((cert,), key),
        )
        assert_configs_work(self.BACKEND, client_config, server_config)

    def test_client_validation(self, client_cert, server_cert, ca_cert):
        """
        A Server and Client context, where the Server context is set to
        validate the client, and the client does not validate, and the client
        presents a cert chain, can handshake.
        """
        server_certfile = self.BACKEND.certificate.from_file(
            server_cert['cert']
        )
        server_keyfile = self.BACKEND.private_key.from_file(server_cert['key'])
        client_certfile = self.BACKEND.certificate.from_file(
            client_cert['cert']
        )
        client_keyfile = self.BACKEND.private_key.from_file(client_cert['key'])
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(
            validate_certificates=False,
            certificate_chain=((client_certfile,), client_keyfile),
        )
        server_config = pep543.TLSConfiguration(
            certificate_chain=((server_certfile,), server_keyfile),
            trust_store=trust_store,
        )
        assert_configs_work(self.BACKEND, client_config, server_config)

    def test_mutual_validation(self, client_cert, server_cert, ca_cert):
        """
        A Server and Client context, where each context is configured to verify
        the other, can handshake.
        """
        server_certfile = self.BACKEND.certificate.from_file(
            server_cert['cert']
        )
        server_keyfile = self.BACKEND.private_key.from_file(server_cert['key'])
        client_certfile = self.BACKEND.certificate.from_file(
            client_cert['cert']
        )
        client_keyfile = self.BACKEND.private_key.from_file(client_cert['key'])
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(
            certificate_chain=((client_certfile,), client_keyfile),
            trust_store=trust_store,
        )
        server_config = pep543.TLSConfiguration(
            certificate_chain=((server_certfile,), server_keyfile),
            trust_store=trust_store,
        )
        assert_configs_work(self.BACKEND, client_config, server_config)

    @pytest.mark.parametrize(
        'inner_protocols,result', (
            ((pep543.NextProtocol.H2, pep543.NextProtocol.HTTP1), pep543.NextProtocol.H2),
            ((b'h2', b'http/1.1'), pep543.NextProtocol.H2),
            ((b'myfavouriteproto',), b'myfavouriteproto'),
        ))
    def test_inner_protocol_overlap(self,
                                    client_cert,
                                    server_cert,
                                    ca_cert,
                                    inner_protocols,
                                    result):
        """
        A Server and Client context, when both contexts support the same inner
        protocols, either successfully negotiate an inner protocol or don't
        negotiate anything.
        """
        server_certfile = self.BACKEND.certificate.from_file(
            server_cert['cert']
        )
        server_keyfile = self.BACKEND.private_key.from_file(server_cert['key'])
        client_certfile = self.BACKEND.certificate.from_file(
            client_cert['cert']
        )
        client_keyfile = self.BACKEND.private_key.from_file(client_cert['key'])
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(
            certificate_chain=((client_certfile,), client_keyfile),
            trust_store=trust_store,
            inner_protocols=inner_protocols
        )
        server_config = pep543.TLSConfiguration(
            certificate_chain=((server_certfile,), server_keyfile),
            trust_store=trust_store,
            inner_protocols=inner_protocols
        )
        client, server = assert_configs_work(
            self.BACKEND, client_config, server_config
        )

        assert client.negotiated_protocol() in (result, None)
        assert server.negotiated_protocol() in (result, None)

    def test_can_detect_tls_protocol(self, server_cert, ca_cert):
        """
        A Server and Client context that successfully handshake will report the
        same TLS version.
        """
        server_certfile = self.BACKEND.certificate.from_file(
            server_cert['cert']
        )
        server_keyfile = self.BACKEND.private_key.from_file(server_cert['key'])
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(
            trust_store=trust_store
        )
        server_config = pep543.TLSConfiguration(
            certificate_chain=((server_certfile,), server_keyfile),
            validate_certificates=False,
        )
        client, server = assert_configs_work(
            self.BACKEND, client_config, server_config
        )

        assert client.negotiated_tls_version() in pep543.TLSVersion
        assert server.negotiated_tls_version() in pep543.TLSVersion
        assert (
            client.negotiated_tls_version() == server.negotiated_tls_version()
        )
