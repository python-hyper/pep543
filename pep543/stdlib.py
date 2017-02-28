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
    TLSVersion.TLSv1_3: _OP_NO_SSLv2 | _OP_NO_SSLv3 | _OP_NO_TLSv1 | _OP_NO_TLSv1_1 | _OP_NO_TLSv1_2,
}
_opts_from_max_version = {
    TLSVersion.SSLv2: _OP_NO_TLSv1_3 | _OP_NO_TLSv1_2 | _OP_NO_TLSv1_1 | _OP_NO_TLSv1 | _OP_NO_SSLv3,
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


def _version_options_from_version_range(min, max):
    """
    Given a TLS version range, we need to convert that into options that
    exclude TLS versions as appropriate.
    """
    try:
        return _opts_from_min_version[min] | _opts_from_max_version[max]
    except KeyError:
        raise TLSError("Bad maximum/minimum options")


def _init_context(config):
    """
    Initialize an ssl.SSLContext object with a given configuration.
    """
    some_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    some_context.options |= ssl.OP_NO_COMPRESSION

    if not config.validate_certificates:
        some_context.check_hostname = False
        some_context.verify_mode = ssl.CERT_NONE
    else:
        # Load the trust stores.
        for trust_store in config.trust_stores:
            if trust_store is _SYSTEMTRUSTSTORE:
                some_context.load_default_certs()
                continue

        some_context.load_verify_locations(trust_store._trust_path)

    if config.certificate_chain:
        # FIXME: support multiple certificates at different filesystem
        # locations. This requires being prepared to create temporary
        # files.
        cert_chain = config.certificate_chain
        assert len(cert_chain[0]) == 1
        cert_path = cert_chain[0]._cert_path
        key_path = None
        password = None
        if cert_chain:
            key_path = cert_chain[1]._key_path
            password = cert_chain[1]._password

        some_context.load_cert_chain(cert_path, key_path, password)

    # Set the cipher suites.
    ossl_names = [_cipher_map[cipher] for cipher in config.ciphers]
    ctx.set_ciphers(':'.join(ossl_names))

    if config.inner_protocols:
        protocols = []
        for np in config.inner_protocols:
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
    def __init__(self, buffer=None, path=None, password=None):
        self._key_buffer = buffer
        self._key_path = path
        self._password = password

    @classmethod
    def from_buffer(cls, buffer, password=None):
        return cls(buffer=buffer, password=password)

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
