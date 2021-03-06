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

        client_bytes = client.peek_outgoing(client.bytes_buffered())
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

        server_bytes = server.peek_outgoing(server.bytes_buffered())
        if server_bytes:
            client.receive_from_network(server_bytes)
            server.consume_outgoing(len(server_bytes))


def write_until_complete(writer, reader, message):
    """
    Writes a given message via the writer and sends the bytes to the reader
    until complete.
    """
    message_written = False
    while not message_written:
        try:
            writer.write(message)
        except pep543.WantWriteError:
            pass
        else:
            message_written = True

        written_data = writer.peek_outgoing(writer.bytes_buffered())
        writer.consume_outgoing(len(written_data))
        if written_data:
            reader.receive_from_network(written_data)


def write_until_read(writer, reader, message):
    """
    Writes a given message into the writer until the reader reads it.
    """
    write_until_complete(writer, reader, message)
    # For the sake of detecting errors we'll ask to read *too much*.
    assert reader.read(len(message) * 2) == message


def handshake_buffers(client, server, hostname=None):
    """
    Do a handshake in memory, getting back two buffer objects.
    """
    client_buffer = client.wrap_buffers(hostname)
    server_buffer = server.wrap_buffers()
    loop_until_success(client_buffer, server_buffer, 'do_handshake')
    return client_buffer, server_buffer


def assert_configs_work(backend, client_config, server_config, hostname=None):
    """
    Given a pair of configs (one for the client, and one for the server),
    creates contexts and buffers, performs a handshake, and then sends a bit of
    test data to confirm the connection is up.

    Returns the client and server connection.
    """
    client_context = backend.client_context(client_config)
    server_context = backend.server_context(server_config)
    client, server = handshake_buffers(client_context, server_context, hostname)
    assert client.context is client_context
    assert server.context is server_context
    write_until_read(client, server, HTTP_REQUEST)
    write_until_read(server, client, HTTP_RESPONSE)
    return client, server


def cert_and_key_from_file(backend, cert_fixture):
    """
    Given a cert fixture, loads the cert and key from a file and returns a cert
    chain object that can be used by PEP 543 TLSConfiguration objects.
    """
    cert = backend.certificate.from_file(cert_fixture['cert'])
    key = backend.private_key.from_file(cert_fixture['key'])
    return ((cert,), key)


def cert_and_key_from_buffers(backend, cert_fixture):
    """
    Given a cert fixture, loads the cert and key from a buffer and returns a
    cert chain object that can be used by PEP 543 TLSConfiguration objects.
    """
    with open(cert_fixture['cert'], 'rb') as f:
        cert = backend.certificate.from_buffer(f.read())
    with open(cert_fixture['key'], 'rb') as f:
        key = backend.private_key.from_buffer(f.read())
    return ((cert,), key)


CHAIN_LOADERS = (cert_and_key_from_file, cert_and_key_from_buffers)


class SimpleNegotiation(object):
    """
    These tests do simple TLS negotiation using various configurations.
    """
    BACKEND = None

    def test_client_context_returns_configuration(self, ca_cert):
        """
        A Client context initialized with a given configuration will return the
        configuration it was initialized with.
        """
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])
        client_config = pep543.TLSConfiguration(trust_store=trust_store)
        client_context = self.BACKEND.client_context(client_config)

        assert client_context.configuration is client_config

    @pytest.mark.parametrize('load_chain', CHAIN_LOADERS)
    def test_server_context_returns_configuration(self,
                                                  server_cert,
                                                  load_chain):
        """
        A Server context initialized with a given configuration will return the
        configuration it was initialized with.
        """
        cert_chain = load_chain(self.BACKEND, server_cert)
        server_config = pep543.TLSConfiguration(
            validate_certificates=False,
            certificate_chain=cert_chain,
        )
        server_context = self.BACKEND.server_context(server_config)

        assert server_context.configuration is server_config

    @pytest.mark.parametrize('load_chain', CHAIN_LOADERS)
    def test_no_validation(self, server_cert, load_chain):
        """
        A Server and Client context that both have their validation settings
        disabled and otherwise use the default configuration can handshake.
        """
        cert_chain = load_chain(self.BACKEND, server_cert)
        client_config = pep543.TLSConfiguration(validate_certificates=False)
        server_config = pep543.TLSConfiguration(
            validate_certificates=False,
            certificate_chain=cert_chain,
        )
        assert_configs_work(self.BACKEND, client_config, server_config)

    @pytest.mark.parametrize('load_chain', CHAIN_LOADERS)
    def test_server_validation(self, server_cert, ca_cert, load_chain):
        """
        A Server and Client context, where the Client context is set to
        validate the server, and otherwise use the default configuration,
        can handshake.
        """
        cert_chain = load_chain(self.BACKEND, server_cert)
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(trust_store=trust_store)
        server_config = pep543.TLSConfiguration(
            validate_certificates=False,
            certificate_chain=cert_chain,
        )
        assert_configs_work(self.BACKEND, client_config, server_config)

    @pytest.mark.parametrize('load_chain', CHAIN_LOADERS)
    def test_client_validation(self,
                               client_cert,
                               server_cert,
                               ca_cert,
                               load_chain):
        """
        A Server and Client context, where the Server context is set to
        validate the client, and the client does not validate, and the client
        presents a cert chain, can handshake.
        """
        server_certchain = load_chain(self.BACKEND, server_cert)
        client_certchain = load_chain(self.BACKEND, client_cert)
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(
            validate_certificates=False,
            certificate_chain=client_certchain,
        )
        server_config = pep543.TLSConfiguration(
            certificate_chain=server_certchain,
            trust_store=trust_store,
        )
        assert_configs_work(self.BACKEND, client_config, server_config)

    @pytest.mark.parametrize('load_chain', CHAIN_LOADERS)
    def test_mutual_validation(self,
                               client_cert,
                               server_cert,
                               ca_cert,
                               load_chain):
        """
        A Server and Client context, where each context is configured to verify
        the other, can handshake.
        """
        server_certchain = load_chain(self.BACKEND, server_cert)
        client_certchain = load_chain(self.BACKEND, client_cert)
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(
            certificate_chain=client_certchain,
            trust_store=trust_store,
        )
        server_config = pep543.TLSConfiguration(
            certificate_chain=server_certchain,
            trust_store=trust_store,
        )
        assert_configs_work(self.BACKEND, client_config, server_config)

    @pytest.mark.parametrize('load_chain', CHAIN_LOADERS)
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
                                    result,
                                    load_chain):
        """
        A Server and Client context, when both contexts support the same inner
        protocols, either successfully negotiate an inner protocol or don't
        negotiate anything.
        """
        server_certchain = load_chain(self.BACKEND, server_cert)
        client_certchain = load_chain(self.BACKEND, client_cert)
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(
            certificate_chain=client_certchain,
            trust_store=trust_store,
            inner_protocols=inner_protocols
        )
        server_config = pep543.TLSConfiguration(
            certificate_chain=server_certchain,
            trust_store=trust_store,
            inner_protocols=inner_protocols
        )
        client, server = assert_configs_work(
            self.BACKEND, client_config, server_config
        )

        assert client.negotiated_protocol() in (result, None)
        assert server.negotiated_protocol() in (result, None)

    @pytest.mark.parametrize('load_chain', CHAIN_LOADERS)
    def test_can_detect_tls_protocol(self, server_cert, ca_cert, load_chain):
        """
        A Server and Client context that successfully handshake will report the
        same TLS version.
        """
        cert_chain = load_chain(self.BACKEND, server_cert)
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(
            trust_store=trust_store
        )
        server_config = pep543.TLSConfiguration(
            certificate_chain=cert_chain,
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

    @pytest.mark.parametrize('load_chain', CHAIN_LOADERS)
    def test_no_tls_protocol_before_handhake(self, server_cert, ca_cert, load_chain):
        """
        Before the TLS handshake is done, no TLS protocols is available.
        """
        cert_chain = load_chain(self.BACKEND, server_cert)
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(
            trust_store=trust_store
        )
        server_config = pep543.TLSConfiguration(
            certificate_chain=cert_chain,
            validate_certificates=False,
        )
        client_context = self.BACKEND.client_context(client_config)
        server_context = self.BACKEND.server_context(server_config)

        client_buffer = client_context.wrap_buffers(None)
        server_buffer = server_context.wrap_buffers()

        print(client_buffer.negotiated_tls_version())
        assert client_buffer.negotiated_tls_version() is None
        assert server_buffer.negotiated_tls_version() is None

    @pytest.mark.parametrize('load_chain', CHAIN_LOADERS)
    def test_can_cleanly_shutdown(self, server_cert, ca_cert, load_chain):
        """
        A Server and Client context that successfully handshake can succesfully
        perform a shutdown.
        """
        cert_chain = load_chain(self.BACKEND, server_cert)
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(
            trust_store=trust_store
        )
        server_config = pep543.TLSConfiguration(
            certificate_chain=cert_chain,
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

        # We should also check that readinto returns EOF.
        reference_buffer = bytearray(8192)
        buffer = bytearray(8192)
        assert not client.readinto(buffer, 8192)
        assert buffer == reference_buffer
        assert not server.readinto(buffer, 8192)
        assert buffer == reference_buffer

        # And writes should raise errors.
        with pytest.raises(pep543.TLSError):
            client.write(b'will fail')
        with pytest.raises(pep543.TLSError):
            server.write(b'will fail')

    @pytest.mark.parametrize('load_chain', CHAIN_LOADERS)
    def test_can_detect_cipher(self, server_cert, ca_cert, load_chain):
        """
        A Server and Client context that successfully handshake will report the
        same cipher.
        """
        cert_chain = load_chain(self.BACKEND, server_cert)
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(
            trust_store=trust_store
        )
        server_config = pep543.TLSConfiguration(
            certificate_chain=cert_chain,
            validate_certificates=False,
        )
        client, server = assert_configs_work(
            self.BACKEND, client_config, server_config
        )

        # The cipher should be either a CipherSuite or an int, and should match
        # the server.
        assert isinstance(client.cipher(), (pep543.CipherSuite, int))
        assert isinstance(server.cipher(), (pep543.CipherSuite, int))
        assert client.cipher() == server.cipher()

    @pytest.mark.parametrize('load_chain', CHAIN_LOADERS)
    def test_readinto(self, server_cert, ca_cert, load_chain):
        """
        A Server and Client context that successfully handshake can write
        bytes into buffers.
        """
        cert_chain = load_chain(self.BACKEND, server_cert)
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(
            trust_store=trust_store
        )
        server_config = pep543.TLSConfiguration(
            certificate_chain=cert_chain,
            validate_certificates=False,
        )
        client, server = assert_configs_work(
            self.BACKEND, client_config, server_config
        )

        # Firstly, test that if we send some data to the server, we can use
        # readinto to read it. We'll allocate a buffer that's too big and
        # check that it gets filled.
        message_size = len(HTTP_REQUEST)
        test_buffer = bytearray(message_size * 2)
        write_until_complete(client, server, HTTP_REQUEST)
        read_length = server.readinto(test_buffer, message_size * 2)
        assert read_length == message_size
        assert test_buffer[:message_size] == HTTP_REQUEST

        # Next, test that if we ask for more data than the buffer can hold we
        # just get the amount that fills the buffer.
        message_size = len(HTTP_RESPONSE)
        test_buffer = bytearray(message_size // 2)
        write_until_complete(server, client, HTTP_RESPONSE)
        read_length = client.readinto(test_buffer, message_size * 2)
        assert read_length == (message_size // 2)
        assert (
            test_buffer[:message_size // 2] == HTTP_RESPONSE[:message_size // 2]
        )

    @pytest.mark.parametrize('load_chain', CHAIN_LOADERS)
    @pytest.mark.parametrize('hostname', [None, 'localhost'])
    def test_snicallback_fires_with_data(self,
                                         server_cert,
                                         ca_cert,
                                         load_chain,
                                         hostname):
        """
        In a basic, successful TLS negotiation, the SNI callback will be fired
        and will provide the appropriate data.
        """
        callback_args = []

        def callback(*args):
            callback_args.append(args)
            return args[-1]

        cert_chain = load_chain(self.BACKEND, server_cert)
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(
            trust_store=trust_store
        )
        server_config = pep543.TLSConfiguration(
            certificate_chain=cert_chain,
            validate_certificates=False,
            sni_callback=callback
        )
        client, server = assert_configs_work(
            self.BACKEND, client_config, server_config, hostname=hostname
        )

        assert len(callback_args) == 1
        conn_object, name, config = callback_args[0]

        assert conn_object is server
        assert config == server_config
        assert name == hostname

    @pytest.mark.parametrize('load_chain', CHAIN_LOADERS)
    @pytest.mark.parametrize('rval', (None, object()))
    def test_snicallback_fails_with_none(self,
                                         server_cert,
                                         ca_cert,
                                         load_chain,
                                         rval):
        """
        If the SNI callback returns any non TLSConfiguration value, the
        handshake fails.
        """
        callback_args = []

        def callback(*args):
            callback_args.append(args)
            return rval

        cert_chain = load_chain(self.BACKEND, server_cert)
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(
            trust_store=trust_store
        )
        server_config = pep543.TLSConfiguration(
            certificate_chain=cert_chain,
            validate_certificates=False,
            sni_callback=callback
        )
        # TODO: This is really overbroad, this error could come from anywhere.
        with pytest.raises(pep543.TLSError):
            assert_configs_work(
                self.BACKEND, client_config, server_config
            )

        assert callback_args

    @pytest.mark.parametrize('load_chain', CHAIN_LOADERS)
    def test_snicallback_fails_with_exception(self,
                                              server_cert,
                                              ca_cert,
                                              load_chain):
        """
        If the SNI callback raises an exception, the handshake fails.
        """
        callback_args = []

        def callback(*args):
            callback_args.append(args)
            raise ValueError("Whoops!")

        cert_chain = load_chain(self.BACKEND, server_cert)
        trust_store = self.BACKEND.trust_store.from_pem_file(ca_cert['cert'])

        client_config = pep543.TLSConfiguration(
            trust_store=trust_store
        )
        server_config = pep543.TLSConfiguration(
            certificate_chain=cert_chain,
            validate_certificates=False,
            sni_callback=callback
        )
        # TODO: This is really overbroad, this error could come from anywhere.
        # We allow either the underlying error or TLSError here.
        with pytest.raises((pep543.TLSError, ValueError)):
            assert_configs_work(
                self.BACKEND, client_config, server_config
            )

        assert callback_args
