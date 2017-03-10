# -*- coding: utf-8 -*-
"""
Stdlib Shim
~~~~~~~~~~~

This module shims the standard library OpenSSL module into the PEP 543 API.
"""
import os
import ssl
import tempfile

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
    TrustStore,
    WantReadError,
    WantWriteError
)

from contextlib import contextmanager


# We need all the various TLS options. We hard code this as their integer
# values to deal with the fact that the symbolic constants are only exposed if
# both OpenSSL and Python agree that they should be. That's problematic for
# something that should be generic. This way works better.
_OP_NO_SSLv2 = 0x01000000
_OP_NO_SSLv3 = 0x02000000
_OP_NO_TLSv1 = 0x04000000
_OP_NO_TLSv1_2 = 0x08000000
_OP_NO_TLSv1_1 = 0x10000000
_OP_NO_TLSv1_3 = 0x20000000

_opts_from_min_version = {
    TLSVersion.MINIMUM_SUPPORTED: 0,
    TLSVersion.SSLv2: 0,
    TLSVersion.SSLv3: _OP_NO_SSLv2,
    TLSVersion.TLSv1: _OP_NO_SSLv2 | _OP_NO_SSLv3,
    TLSVersion.TLSv1_1: _OP_NO_SSLv2 | _OP_NO_SSLv3 | _OP_NO_TLSv1,
    TLSVersion.TLSv1_2: _OP_NO_SSLv2 | _OP_NO_SSLv3 | _OP_NO_TLSv1 | _OP_NO_TLSv1_1,
    TLSVersion.TLSv1_3: (
        _OP_NO_SSLv2 | _OP_NO_SSLv3 | _OP_NO_TLSv1 | _OP_NO_TLSv1_1 | _OP_NO_TLSv1_2
    ),
}
_opts_from_max_version = {
    TLSVersion.SSLv2: (
        _OP_NO_TLSv1_3 | _OP_NO_TLSv1_2 | _OP_NO_TLSv1_1 | _OP_NO_TLSv1 | _OP_NO_SSLv3
    ),
    TLSVersion.SSLv3: _OP_NO_TLSv1_3 | _OP_NO_TLSv1_2 | _OP_NO_TLSv1_1 | _OP_NO_TLSv1,
    TLSVersion.TLSv1: _OP_NO_TLSv1_3 | _OP_NO_TLSv1_2 | _OP_NO_TLSv1_1,
    TLSVersion.TLSv1_1: _OP_NO_TLSv1_3 | _OP_NO_TLSv1_2,
    TLSVersion.TLSv1_2: _OP_NO_TLSv1_3,
    TLSVersion.TLSv1_3: 0,
    TLSVersion.MAXIMUM_SUPPORTED: 0
}


# We need to populate a dictionary of ciphers that OpenSSL supports, in the
# form of {16-bit number: OpenSSL suite name}.
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
ctx.set_ciphers('ALL:COMPLEMENTOFALL')
_cipher_map = {c['id'] & 0xffff: c['name'] for c in ctx.get_ciphers()}
del ctx


@contextmanager
def _error_converter(ignore_filter=()):
    """
    Catches errors from the ssl module and wraps them up in TLSError
    exceptions. Ignores certain kinds of exceptions as requested.
    """
    try:
        yield
    except ignore_filter:
        raise
    except ssl.SSLWantReadError:
        raise WantReadError("Must read data") from None
    except ssl.SSLWantWriteError:
        raise WantWriteError("Must write data") from None
    except ssl.SSLError as e:
        raise TLSError(e) from None


def _version_options_from_version_range(min, max):
    """
    Given a TLS version range, we need to convert that into options that
    exclude TLS versions as appropriate.
    """
    try:
        return _opts_from_min_version[min] | _opts_from_max_version[max]
    except KeyError:
        raise TLSError("Bad maximum/minimum options")


def _configure_context_for_validation(context, validate, trust_store):
    """
    Given an SSLContext object, configures it for certificate validation based
    on the validate_certificates and trust_store properties of the PEP 543
    config.

    Returns the context.
    """
    if not validate:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        # Load the trust store
        if trust_store is _SYSTEMTRUSTSTORE:
            context.load_default_certs()
        else:
            context.load_verify_locations(trust_store._trust_path)

    return context


def _configure_context_for_certs(context, cert_chain):
    """
    Given a PEP 543 cert chain, configure the SSLContext to send that cert
    chain in the handshake.

    Returns the context.
    """
    if cert_chain:
        # FIXME: support multiple certificates at different filesystem
        # locations. This requires being prepared to create temporary
        # files.
        assert len(cert_chain[0]) == 1
        cert_path = cert_chain[0][0]._cert_path
        key_path = None
        password = None
        if cert_chain[1]:
            key_path = cert_chain[1]._key_path
            password = cert_chain[1]._password

        context.load_cert_chain(cert_path, key_path, password)

    return context


def _configure_context_for_ciphers(context, ciphers):
    """
    Given a PEP 543 cipher suite list, configure the SSLContext to use those
    cipher suites.

    Returns the context.
    """
    ossl_names = [
        _cipher_map[cipher] for cipher in ciphers
        if cipher in _cipher_map
    ]
    if not ossl_names:
        raise TLSError("Unable to find any supported ciphers!")
    context.set_ciphers(':'.join(ossl_names))
    return context


def _configure_context_for_negotiation(context, inner_protocols):
    """
    Given a PEP 543 list of protocols to negotiate, configures the SSLContext
    to negotiate those protocols.
    """
    if inner_protocols:
        protocols = []
        for np in inner_protocols:
            proto_string = np if isinstance(np, bytes) else np.value
            # The protocol string needs to be of type str for the standard
            # library.
            protocols.append(proto_string.decode('ascii'))

        # If ALPN/NPN aren't supported, that's no problem.
        try:
            context.set_alpn_protocols(protocols)
        except NotImplementedError:
            pass

        try:
            context.set_npn_protocols(protocols)
        except NotImplementedError:
            pass

    return context


def _init_context(config):
    """
    Initialize an ssl.SSLContext object with a given configuration.
    """
    some_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    some_context.options |= ssl.OP_NO_COMPRESSION

    some_context = _configure_context_for_validation(
        some_context, config.validate_certificates, config.trust_store
    )
    some_context = _configure_context_for_certs(
        some_context, config.certificate_chain
    )
    some_context = _configure_context_for_ciphers(
        some_context, config.ciphers
    )
    some_context = _configure_context_for_negotiation(
        some_context, config.inner_protocols
    )
    some_context.options |= _version_options_from_version_range(
        config.lowest_supported_version,
        config.highest_supported_version,
    )
    # TODO: Add ServerNameCallback
    return some_context


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

        # We need to track whether the connection is established to properly
        # report the TLS version. This is to work around a Python bug:
        # https://bugs.python.org/issue29781
        self._connection_established = False

    def read(self, amt):
        try:
            with _error_converter(ignore_filter=ssl.SSLZeroReturnError):
                return self._object.read(amt)
        except ssl.SSLZeroReturnError:
            return b''

    def readinto(self, buffer, amt):
        try:
            with _error_converter(ignore_filter=ssl.SSLZeroReturnError):
                return self._object.read(amt, buffer)
        except ssl.SSLZeroReturnError:
            return 0

    def write(self, buf):
        with _error_converter():
            return self._object.write(buf)

    def do_handshake(self):
        with _error_converter():
            rc = self._object.do_handshake()

        self._connection_established = True
        return rc

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
            raise TLSError("Unable to identify cipher suite")

        cipher_id = cipher['id'] & 0xffff
        try:
            return CipherSuite(cipher_id)
        except ValueError:
            return cipher_id

    def negotiated_protocol(self):
        proto = self._object.selected_alpn_protocol()
        if proto is None:
            proto = self._object.selected_npn_protocol()

        # The standard library returns this as a str, we want bytes.
        if proto is not None:
            proto = proto.encode('ascii')

        try:
            return NextProtocol(proto)
        except ValueError:
            return proto

    @property
    def context(self):
        return self._parent_context

    def negotiated_tls_version(self):
        if not self._connection_established:
            return None

        ossl_version = self._object.version()
        return TLSVersion(ossl_version)

    def shutdown(self):
        with _error_converter():
            rc = self._object.unwrap()

        self._connection_established = False
        return rc

    def receive_from_network(self, data):
        # TODO: This method returns a length. Can it return short? What do we
        # do if it does?
        written_len = self._in_bio.write(data)
        assert written_len == len(data)

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

    def bytes_buffered(self):
        return self._out_bio.pending


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
        ossl_context = _init_context(self._configuration)
        return OpenSSLWrappedBuffer(self, ossl_context, server_hostname)


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
        ossl_context = _init_context(self._configuration)
        return OpenSSLWrappedBuffer(self, ossl_context, server_hostname=None)


class OpenSSLCertificate(Certificate):
    """
    A handle to a certificate object, either on disk or in a buffer, that can
    be used for either server or client connectivity.
    """
    def __init__(self, path=None):
        self._cert_path = path

    @classmethod
    def from_buffer(cls, buffer):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, 'wb') as f:
            f.write(buffer)
        return cls(path=path)

    @classmethod
    def from_file(cls, path):
        return cls(path=path)


class OpenSSLPrivateKey(PrivateKey):
    """
    A handle to a private key object, either on disk or in a buffer, that can
    be used along with a certificate for either server or client connectivity.
    """
    def __init__(self, path=None, password=None):
        self._key_path = path
        self._password = password

    @classmethod
    def from_buffer(cls, buffer, password=None):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, 'wb') as f:
            f.write(buffer)
        return cls(path=path, password=password)

    @classmethod
    def from_file(cls, path, password=None):
        return cls(path=path, password=password)


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
