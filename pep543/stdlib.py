# -*- coding: utf-8 -*-
"""
Stdlib Shim
~~~~~~~~~~~

This module shims the standard library OpenSSL module into the PEP 543 API.
"""
import ssl

from . import (
    Backend, ClientContext, ServerContext, Certificate, PrivateKey, TrustStore
)

class OpenSSLClientContext(ClientContext):
    """
    This class controls and creates wrapped sockets and buffers for using the
    standard library bindings to OpenSSL to perform TLS connections on the
    client side of a network connection.
    """
    def __init__(self, configuration):
        self._configuration = configuration

    @property
    def configuration(self):
        return self._configuration

    def wrap_buffers(self, server_hostname):
        """
        Create a buffered I/O object that can be used to do TLS.
        """
        pass


class OpenSSLServerContext(ServerContext):
    """
    This class controls and creates wrapped sockets and buffers for using the
    standard library bindings to OpenSSL to perform TLS connections on the
    server side of a network connection.
    """
    def __init__(self, configuration):
        self._configuration = configuration

    @property
    def configuration(self):
        return self._configuration

    def wrap_buffers(self):
        """
        Create a buffered I/O object that can be used to do TLS.
        """
        pass


class OpenSSLCertificate(Certificate):
    """
    A handle to a certificate object, either on disk or in a buffer, that can
    be used for either server or client connectivity.
    """
    pass


class OpenSSLPrivateKey(PrivateKey):
    """
    A handle to a private key object, either on disk or in a buffer, that can
    be used along with a certificate for either server or client connectivity.
    """
    pass


class OpenSSLTrustStore(TrustStore):
    """
    A handle to a trust store object, either on disk or the system trust store,
    that can be used to validate the certificates presented by a remote peer.
    """
    pass


#: The stdlib ``Backend`` object.
STDLIB_BACKEND = Backend(
    client_context=OpenSSLClientContext,
    server_context=OpenSSLServerContext,
    certificate=OpenSSLCertificate,
    private_key=OpenSSLPrivateKey,
    trust_store=OpenSSLTrustStore
)
