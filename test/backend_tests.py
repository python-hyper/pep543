# -*- coding: utf-8 -*-
"""
A module containing a collection of tests that all backends should be able to
pass. Tests for a specific backend can be written by importing all classes from
this file and setting their class-scoped BACKEND variable to the appropriate
backend.
"""
import pep543

import pytest


# Some non-trivial sample data to send through the connections to confirm that
# they work.
HTTP_REQUEST = (
    b'GET /en/latest/ HTTP/1.1\r\n'
    b'Host: hyper.readthedocs.io\r\n'
    b'Connection: keep-alive\r\n'
    b'Upgrade-Insecure-Requests: 1\r\n'
    b'User-Agent: Mozilla/5.0\r\n'
    b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n'
    b'Accept-Encoding: gzip, deflate, sdch, br\r\n'
    b'Accept-Language: en-US,en;q=0.8\r\n'
    b'\r\n'
)
HTTP_RESPONSE = (
    b'HTTP/1.1 200 OK\r\n'
    b'Server: nginx/1.10.0 (Ubuntu)\r\n'
    b'Date: Mon, 06 Mar 2017 12:35:18 GMT\r\n'
    b'Content-Type: text/html\r\n'
    b'Last-Modified: Sat, 08 Oct 2016 00:39:59 GMT\r\n'
    b'Transfer-Encoding: chunked\r\n'
    b'Connection: keep-alive\r\n'
    b'Vary: Accept-Encoding\r\n'
    b'ETag: W/"57f8405f-444d"\r\n'
    b'X-Subdomain-TryFiles: True\r\n'
    b'X-Served: Nginx\r\n'
    b'X-Deity: web03\r\n'
    b'Content-Encoding: gzip\r\n'
    b'\r\n'
)


def loop_until_success(client, server, func):
    """
    Given a function to call on a client and server, repeatedly loops over the
    client and server and calls that function until they both stop erroring.
    """
    client_complete = server_complete = False
    client_func = getattr(client, func)
    server_func = getattr(server, func)

    while not (client_complete and server_complete):
        while not client_complete:
            try:
                client_func()
            except (pep543.WantWriteError, pep543.WantReadError):
                break
            else:
                client_complete = True

        client_bytes = client.peek_outgoing(8192)
        if client_bytes:
            server.receive_from_network(client_bytes)
            client.consume_outgoing(len(client_bytes))

        while not server_complete:
            try:
                server_func()
            except (pep543.WantWriteError, pep543.WantReadError):
                break
            else:
                server_complete = True

        server_bytes = server.peek_outgoing(8192)
        if server_bytes:
            client.receive_from_network(server_bytes)
            server.consume_outgoing(len(server_bytes))


def write_until_read(writer, reader, message):
    """
    Writes a given message into the writer until the reader reads it.
    """
    # First, we need to write. This may require multiple calls to write.
    message_written = False
    while not message_written:
        try:
            writer.write(message)
        except pep543.WantWriteError:
            pass
        else:
            message_written = True

        # This times 5 nonsense is a hack to tolerate the fact that we can't
        # check how much data is there. We should amend the PEP to allow us to
        # ask that question.
        written_data = writer.peek_outgoing(len(message) * 5)
        writer.consume_outgoing(len(written_data))
        if written_data:
            reader.receive_from_network(written_data)

    # Ok, all the data is written and the remote peer should have received it
    # all. We should now be able to read it. For the sake of detecting errors
    # we'll ask to read *too much*.
    assert reader.read(len(message) * 2) == message


def handshake_buffers(client, server, hostname=None):
    """
    Do a handshake in memory, getting back two buffer objects.
    """
    client_buffer = client.wrap_buffers(hostname)
    server_buffer = server.wrap_buffers()
    loop_until_success(client_buffer, server_buffer, 'do_handshake')
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
    assert client.context is client_context
    assert server.context is server_context
    write_until_read(client, server, HTTP_REQUEST)
    write_until_read(server, client, HTTP_RESPONSE)
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

    def test_can_cleanly_shutdown(self, server_cert, ca_cert):
        """
        A Server and Client context that successfully handshake can succesfully
        perform a shutdown.
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

        # We want to perform a shutdown now.
        loop_until_success(client, server, 'shutdown')

        # At this point, we should read EOF from both client and server.
        assert not client.read(8192)
        assert not server.read(8192)

        # And writes should raise errors.
        with pytest.raises(pep543.TLSError):
            client.write(b'will fail')
        with pytest.raises(pep543.TLSError):
            server.write(b'will fail')
