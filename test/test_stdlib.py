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


def assert_wrap_fails(context, exception):
    """
    A convenient helper that calls wrap_buffers with the appropriate number of
    arugments and asserts that it raises the appropriate error.
    """
    if isinstance(context, pep543.stdlib.STDLIB_BACKEND.client_context):
        with pytest.raises(exception):
            context.wrap_buffers(server_hostname=None)
    else:
        with pytest.raises(exception):
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
        assert_wrap_fails(ctx, pep543.TLSError)
