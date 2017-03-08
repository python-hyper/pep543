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
    arugments.
    """
    if isinstance(context, pep543.stdlib.STDLIB_BACKEND.client_context):
        context.wrap_buffers(server_hostname=None)
    else:
        context.wrap_buffers()


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
        Using TLSConfiguration objects with a bad value for their minimum
        version raises a TLSError with Client contexts.
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
        Using TLSConfiguration objects that have only unsupporetd cipher suites
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
