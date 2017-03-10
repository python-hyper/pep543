# -*- coding: utf-8 -*-
"""
Tests for the standard library PEP 543 shim.
"""
import pep543
import pep543.stdlib

import pytest

from .backend_tests import SimpleNegotiation


CONTEXTS = (
    pep543.stdlib.STDLIB_BACKEND.client_context,
    pep543.stdlib.STDLIB_BACKEND.server_context
 )


def wrap_buffers(context):
    """
    A convenient helper that calls wrap_buffers with the appropriate number of
    arguments.
    """
    if isinstance(context, pep543.stdlib.STDLIB_BACKEND.client_context):
        return context.wrap_buffers(server_hostname=None)
    else:
        return context.wrap_buffers()


class TestSimpleNegotiationStdlib(SimpleNegotiation):
    BACKEND = pep543.stdlib.STDLIB_BACKEND


class TestStdlibErrorHandling(object):
    """
    Validate that the stdlib backend can do sensible error handling in specific
    situations that it cannot handle.
    """
    @pytest.mark.parametrize(
        'lowest,highest', (
            (object(), None), (None, object()), (object(), object())
        )
    )
    @pytest.mark.parametrize('context', CONTEXTS)
    def test_bad_values_for_versions_client(self, lowest, highest, context):
        """
        Using TLSConfiguration objects with a bad value for their minimum or
        maximum version raises a TLSError with Client contexts.
        """
        config = pep543.TLSConfiguration(
            validate_certificates=False,
            lowest_supported_version=lowest,
            highest_supported_version=highest
        )
        ctx = context(config)
        with pytest.raises(pep543.TLSError):
            wrap_buffers(ctx)

    @pytest.mark.parametrize('context', CONTEXTS)
    def test_no_supported_cipher_suites(self, context):
        """
        Using TLSConfiguration objects that have only unsupported cipher suites
        raises a TLSError.
        """
        # We assume that no cipher suite will be defined with the code eeee.
        config = pep543.TLSConfiguration(
            ciphers=[0xeeee],
            trust_store=pep543.stdlib.STDLIB_BACKEND.trust_store.system()
        )
        ctx = context(config)
        with pytest.raises(pep543.TLSError) as e:
            wrap_buffers(ctx)

        assert "supported ciphers" in str(e)


class TestStdlibImplementation(object):
    """
    Tests that ensure that specific implementation details of the stdlib shim
    work the way we want.
    """
    @pytest.mark.parametrize('context', CONTEXTS)
    def test_system_trust_store_loads(self, monkeypatch, context):
        """
        When a context is instructed to load the system trust store, it calls
        load_default_certs.
        """
        calls = 0

        def load_default_certs(*args):
            nonlocal calls
            calls += 1

        monkeypatch.setattr(
            'ssl.SSLContext.load_default_certs', load_default_certs
        )

        config = pep543.TLSConfiguration(
            trust_store=pep543.stdlib.STDLIB_BACKEND.trust_store.system()
        )
        ctx = context(config)
        wrap_buffers(ctx)

        assert calls == 1

    @pytest.mark.parametrize('context', CONTEXTS)
    def test_unknown_cipher_suites(self, monkeypatch, context):
        """
        When a cipher suite returns a cipher that doesn't appear to be
        suppported by the given OpenSSL implementation, a TLSError is raised.
        """
        def unknown_cipher(*args):
            return ('not_a_tls_cipher_suite', None, None)

        monkeypatch.setattr('ssl.SSLObject.cipher', unknown_cipher)

        config = pep543.TLSConfiguration(
            trust_store=pep543.stdlib.STDLIB_BACKEND.trust_store.system()
        )
        ctx = context(config)
        buffer = wrap_buffers(ctx)

        with pytest.raises(pep543.TLSError):
            buffer.cipher()


class TestStdlibProtocolNegotiation(object):
    """
    Tests that validate the standard library's protocol negotiation semantics.
    """
    def assert_negotiated_protocol(self, context, negotiated_protocol):
        """
        Test that the protocol negotiated is as expected.
        """
        if negotiated_protocol is not None:
            negotiated_protocol = pep543.NextProtocol(negotiated_protocol)

        config = pep543.TLSConfiguration(
            validate_certificates=False,
            inner_protocols=(pep543.NextProtocol.H2,)
        )
        ctx = context(config)
        buffer = wrap_buffers(ctx)
        assert (buffer.negotiated_protocol() == negotiated_protocol)

    @pytest.mark.parametrize('context', CONTEXTS)
    def test_works_with_just_npn(self, monkeypatch, context):
        """
        If ALPN is not present, protocol negotiation will fall back to NPN.
        """
        negotiated_protocol = b'h2'

        def notimplemented(*args):
            raise NotImplementedError()

        def ignored(*args):
            pass

        def negotiated(*args):
            return negotiated_protocol.decode('utf-8')

        monkeypatch.setattr(
            'ssl.SSLContext.set_alpn_protocols', notimplemented
        )
        monkeypatch.setattr(
            'ssl.SSLObject.selected_alpn_protocol', ignored
        )
        monkeypatch.setattr('ssl.SSLContext.set_npn_protocols', ignored)
        monkeypatch.setattr('ssl.SSLObject.selected_npn_protocol', negotiated)

        self.assert_negotiated_protocol(context, negotiated_protocol)

    @pytest.mark.parametrize('context', CONTEXTS)
    def test_works_with_just_alpn(self, monkeypatch, context):
        """
        If NPN is not present, protocol negotiation will just use ALPN.
        """
        negotiated_protocol = b'h2'

        def notimplemented(*args):
            raise NotImplementedError()

        def ignored(*args):
            pass

        def negotiated(*args):
            return negotiated_protocol.decode('utf-8')

        monkeypatch.setattr('ssl.SSLContext.set_alpn_protocols', ignored)
        monkeypatch.setattr(
            'ssl.SSLObject.selected_alpn_protocol', negotiated
        )
        monkeypatch.setattr('ssl.SSLContext.set_npn_protocols', notimplemented)
        monkeypatch.setattr('ssl.SSLObject.selected_npn_protocol', ignored)

        self.assert_negotiated_protocol(context, negotiated_protocol)

    @pytest.mark.parametrize('context', CONTEXTS)
    def test_prefers_alpn(self, monkeypatch, context):
        """
        If both NPN and ALPN are present, ALPN is preferred to NPN.
        """
        negotiated_protocol = b'h2'

        def ignored(*args):
            pass

        def negotiated(*args):
            return negotiated_protocol.decode('utf-8')

        def wrong(*args):
            return b'this is not right'

        monkeypatch.setattr('ssl.SSLContext.set_alpn_protocols', ignored)
        monkeypatch.setattr(
            'ssl.SSLObject.selected_alpn_protocol', negotiated
        )
        monkeypatch.setattr('ssl.SSLContext.set_npn_protocols', ignored)
        monkeypatch.setattr('ssl.SSLObject.selected_npn_protocol', wrong)

        self.assert_negotiated_protocol(context, negotiated_protocol)

    @pytest.mark.parametrize('context', CONTEXTS)
    def test_no_protocols(self, monkeypatch, context):
        """
        If neither NPN nor ALPN are present, no protocol is negotiated.
        """
        negotiated_protocol = None

        def ignored(*args):
            pass

        monkeypatch.setattr('ssl.SSLContext.set_alpn_protocols', ignored)
        monkeypatch.setattr(
            'ssl.SSLObject.selected_alpn_protocol', ignored
        )
        monkeypatch.setattr('ssl.SSLContext.set_npn_protocols', ignored)
        monkeypatch.setattr('ssl.SSLObject.selected_npn_protocol', ignored)

        self.assert_negotiated_protocol(context, negotiated_protocol)
