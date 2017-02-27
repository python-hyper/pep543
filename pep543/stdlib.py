# -*- coding: utf-8 -*-
"""
Stdlib Shim
~~~~~~~~~~~

This module shims the standard library OpenSSL module into the PEP 543 API.
"""
import ssl

from . import (
    Backend,
    Certificate,
    CipherSuite,
    ClientContext,
    NextProtocol,
    PrivateKey,
    ServerContext,
    TLSError,
    TLSVersion,
    TLSWrappedBuffer,
    TrustStore
)


class OpenSSLWrappedBuffer(TLSWrappedBuffer):
    """
    An in-memory TLS implementation based on OpenSSL.
    """
    def __init__(self, parent_context, ssl_context, server_hostname):
        self._parent_context = parent_context
        self._ssl_context = ssl_context

        # We need this extra buffer to implement the peek/consume API, which
        # the MemoryBIO object does not allow.
        self._ciphertext_buffer = bytearray()

        # Set up the SSLObject we're going to back this with.
        server_side = isinstance(parent_context, ServerContext)
        self._in_bio = ssl.MemoryBIO()
        self._out_bio = ssl.MemoryBIO()
        self._object = ssl_context.wrap_bio(
            self._in_bio,
            self._out_bio,
            server_side=server_side,
            server_hostname=server_hostname
        )

    def read(self, amt):
        return self._object.read(amt)

    def readinto(self, buffer, amt):
        return self._object.read(amt, buffer)

    def write(self, buf):
        return self._object.write(buf)

    def do_handshake(self):
        return self._object.do_handshake()

    def cipher(self):
        # This is the OpenSSL cipher name. We want the ID, which we can get by
        # looking for this entry in the context's list of supported ciphers.
        # FIXME: This works only on 3.6. To get this to work elsewhere, we may
        # need to vendor tlsdb.
        ossl_cipher, _, _ = self._object.cipher()

        for cipher in self._ssl_context.get_ciphers():
            if cipher['name'] == ossl_cipher:
                break
        else:
            return None

        cipher_id = cipher['id'] & 0xffff
        try:
            return CipherSuite(cipher_id)
        except ValueError:
            return cipher_id


    def negotiated_protocol(self):
        proto = self._object.selected_alpn_protocol()
        if proto is None:
            proto = self._object.selected_npn_protocol()

        try:
            return NextProtocol(proto)
        except ValueError:
            return proto

    @property
    def context(self):
        return self._parent_context

    def negotiated_tls_version(self):
        ossl_version = self._object.version()
        if ossl_version is None:
            return None
        return TLSVersion(ossl_version)

    def shutdown(self):
        return self._object.unwrap()

    def receive_from_network(self, data):
        # TODO: This method returns a length. Can it return short? What do we
        # do if it does?
        self._in_bio.write(data)

    def peek_outgoing(self, amt):
        # TODO: Evaluate this for what happens when it's called with no data.
        # What about EOF?
        ciphertext_bytes = len(self._ciphertext_buffer)
        if ciphertext_bytes < amt:
            self._ciphertext_buffer += self._out_bio.read(
                amt - ciphertext_bytes
            )

        return self._ciphertext_buffer[:amt]

    def consume_outgoing(self, amt):
        del self._ciphertext_buffer[:amt]


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
        some_context = ssl.create_default_context()

        if not self._configuration.validate_certificates:
            some_context.check_hostname = False
            some_context.verify_mode = ssl.CERT_NONE

        if self._configuration.certificate_chain:
            # TODO: Do the thing
            pass

        # TODO: Do the thing with the ciphers
        ciphers = self._configuration.ciphers

        if self._configuration.inner_protocols:
            protocols = []
            for np in self._configuration.inner_protocols:
                proto_string = np if isinstance(np, bytes) else np.value
                protocols.append(proto_string)

            # If ALPN/NPN aren't supported, that's no problem.
            try:
                some_context.set_alpn_protocols(protocols)
            except NotImplementedError:
                pass

            try:
                some_context.set_npn_protocols(protocols)
            except NotImplementedError:
                pass

        # TODO: Do the thing with the TLS versions

        for trust_store in self._configuration.trust_stores:
            if trust_store._system


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
    def __init__(self, buffer=None, path=None):
        self._cert_buffer = buffer
        self._cert_path = path

    @classmethod
    def from_buffer(cls, buffer):
        return cls(buffer=buffer)

    @classmethod
    def from_file(cls, path):
        return cls(path=path)


class OpenSSLPrivateKey(PrivateKey):
    """
    A handle to a private key object, either on disk or in a buffer, that can
    be used along with a certificate for either server or client connectivity.
    """
    def __init__(self, buffer=None, path=None):
        self._key_buffer = buffer
        self._key_path = path

    @classmethod
    def from_buffer(cls, buffer):
        return cls(buffer=buffer)

    @classmethod
    def from_file(cls, path):
        return cls(path=path)


class OpenSSLTrustStore(TrustStore):
    """
    A handle to a trust store object, either on disk or the system trust store,
    that can be used to validate the certificates presented by a remote peer.
    """
    def __init__(self, path):
        self._trust_path = path

    @classmethod
    def system(cls):
        return _SYSTEMTRUSTSTORE

    @classmethod
    def from_pem_file(cls, path):
        return cls(path=path)


# We use a sentinel object for the system trust store that is guaranteed not
# to compare equal to any other object.
_SYSTEMTRUSTSTORE = OpenSSLTrustStore(object())


#: The stdlib ``Backend`` object.
STDLIB_BACKEND = Backend(
    client_context=OpenSSLClientContext,
    server_context=OpenSSLServerContext,
    certificate=OpenSSLCertificate,
    private_key=OpenSSLPrivateKey,
    trust_store=OpenSSLTrustStore
)
