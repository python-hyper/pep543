# -*- coding: utf-8 -*-
"""
Abstract interface to TLS for Python
"""
from abc import ABCMeta, abstractmethod, abstractproperty
from enum import Enum, IntEnum

__all__ = [
    'TLSConfiguration', 'ClientContext', 'ServerContext', 'TLSWrappedBuffer',
    'TLSWrappedSocket', 'CipherSuite', 'NextProtocol', 'TLSVersion',
    'TLSError', 'WantWriteError', 'WantReadError', 'RaggedEOF', 'Certificate',
    'PrivateKey', 'TrustStore', 'Backend'
]


_DEFAULT_VALUE = object()




class TLSConfiguration(object):
    """
    An immutable TLS Configuration object. This object has the following
    properties:

    :param validate_certificates bool: Whether to validate the TLS
        certificates. This switch operates at a very broad scope: either
        validation is enabled, in which case all forms of validation are
        performed including hostname validation if possible, or validation
        is disabled, in which case no validation is performed.

        Not all backends support having their certificate validation
        disabled. If a backend does not support having their certificate
        validation disabled, attempting to set this property to ``False``
        will throw a ``TLSError`` when this object is passed into a
        context object.

    :param certificate_chain Tuple[Tuple[Certificate],PrivateKey]: The
        certificate, intermediate certificates, and the corresponding
        private key for the leaf certificate. These certificates will be
        offered to the remote peer during the handshake if required.

        The first Certificate in the list must be the leaf certificate. All
        subsequent certificates will be offered as intermediate additional
        certificates.

    :param ciphers Tuple[Union[CipherSuite, int]]:
        The available ciphers for TLS connections created with this
        configuration, in priority order.

    :param inner_protocols Tuple[Union[NextProtocol, bytes]]:
        Protocols that connections created with this configuration should
        advertise as supported during the TLS handshake. These may be
        advertised using either or both of ALPN or NPN. This list of
        protocols should be ordered by preference.

    :param lowest_supported_version TLSVersion:
        The minimum version of TLS that should be allowed on TLS
        connections using this configuration.

    :param highest_supported_version TLSVersion:
        The maximum version of TLS that should be allowed on TLS
        connections using this configuration.

    :param trust_store TrustStore:
        The trust store that connections using this configuration will use
        to validate certificates.

    :param sni_callback Optional[ServerNameCallback]:
        A callback function that will be called after the TLS Client Hello
        handshake message has been received by the TLS server when the TLS
        client specifies a server name indication.

        Only one callback can be set per ``TLSConfiguration``. If the
        ``sni_callback`` is ``None`` then the callback is disabled. If the
        ``TLSConfiguration`` is used for a ``ClientContext`` then this
        setting will be ignored.

        The ``callback`` function will be called with three arguments: the
        first will be the ``TLSBufferObject`` for the connection; the
        second will be a string that represents the server name that the
        client is intending to communicate (or ``None`` if the TLS Client
        Hello does not contain a server name); and the third argument will
        be the original ``TLSConfiguration`` that configured the
        connection. The server name argument will be the IDNA *decoded*
        server name.

        The ``callback`` must return a ``TLSConfiguration`` to allow
        negotiation to continue. Other return values signal errors.
        Attempting to control what error is signaled by the underlying TLS
        implementation is not specified in this API, but is up to the
        concrete implementation to handle.

        The Context will do its best to apply the ``TLSConfiguration``
        changes from its original configuration to the incoming connection.
        This will usually include changing the certificate chain, but may
        also include changes to allowable ciphers or any other
        configuration settings.
    """
    __slots__ = (
        '_validate_certificates', '_certificate_chain', '_ciphers',
        '_inner_protocols', '_lowest_supported_version',
        '_highest_supported_version', '_trust_store', '_sni_callback'
    )

    def __init__(self, validate_certificates=None,
                       certificate_chain=None,
                       ciphers=None,
                       inner_protocols=None,
                       lowest_supported_version=None,
                       highest_supported_version=None,
                       trust_store=None,
                       sni_callback=None):

        if validate_certificates is None:
            validate_certificates = True

        if ciphers is None:
            ciphers = DEFAULT_CIPHER_LIST

        if inner_protocols is None:
            inner_protocols = ()

        if lowest_supported_version is None:
            lowest_supported_version = TLSVersion.TLSv1

        if highest_supported_version is None:
            highest_supported_version = TLSVersion.MAXIMUM_SUPPORTED

        self._validate_certificates = validate_certificates
        self._certificate_chain = certificate_chain
        self._ciphers = ciphers
        self._inner_protocols = inner_protocols
        self._lowest_supported_version = lowest_supported_version
        self._highest_supported_version = highest_supported_version
        self._trust_store = trust_store
        self._sni_callback = sni_callback

    def update(self, validate_certificates=_DEFAULT_VALUE,
                     certificate_chain=_DEFAULT_VALUE,
                     ciphers=_DEFAULT_VALUE,
                     inner_protocols=_DEFAULT_VALUE,
                     lowest_supported_version=_DEFAULT_VALUE,
                     highest_supported_version=_DEFAULT_VALUE,
                     trust_store=_DEFAULT_VALUE,
                     sni_callback=_DEFAULT_VALUE):
        """
        Create a new ``TLSConfiguration``, overriding some of the settings
        on the original configuration with the new settings.
        """
        if validate_certificates is _DEFAULT_VALUE:
            validate_certificates = self.validate_certificates

        if certificate_chain is _DEFAULT_VALUE:
            certificate_chain = self.certificate_chain

        if ciphers is _DEFAULT_VALUE:
            ciphers = self.ciphers

        if inner_protocols is _DEFAULT_VALUE:
            inner_protocols = self.inner_protocols

        if lowest_supported_version is _DEFAULT_VALUE:
            lowest_supported_version = self.lowest_supported_version

        if highest_supported_version is _DEFAULT_VALUE:
            highest_supported_version = self.highest_supported_version

        if trust_store is _DEFAULT_VALUE:
            trust_store = self.trust_store

        if sni_callback is _DEFAULT_VALUE:
            sni_callback = self.sni_callback

        return self.__class__(
            validate_certificates, certificate_chain, ciphers,
            inner_protocols, lowest_supported_version,
            highest_supported_version, trust_store, sni_callback
        )

    @property
    def validate_certificates(self):
        """
        Whether to validate the TLS certificates.
        """
        return self._validate_certificates

    @property
    def certificate_chain(self):
        """
        The certificate, intermediate certificates, and the corresponding
        private key for the leaf certificate. These certificates will be
        offered to the remote peer during the handshake if required.

        The first Certificate in the list is the leaf certificate. All
        subsequent certificates will be offered as intermediate additional
        certificates.
        """
        return self._certificate_chain

    @property
    def ciphers(self):
        """
        The available ciphers for TLS connections created with this
        configuration, in priority order.
        """
        return self._ciphers

    @property
    def inner_protocols(self):
        """
        Protocols that connections created with this configuration should
        advertise as supported during the TLS handshake. These may be
        advertised using either or both of ALPN or NPN. This list of
        protocols is ordered by preference.
        """
        return self._inner_protocols

    @property
    def lowest_supported_version(self):
        """
        The minimum version of TLS that is allowed on TLS connections using
        this configuration.
        """
        return self._lowest_supported_version

    @property
    def highest_supported_version(self):
        """
        The maximum version of TLS that will be allowed on TLS connections
        using this configuration.
        """
        return self._highest_supported_version

    @property
    def trust_store(self):
        """
        The trust store that connections using this configuration will use
        to validate certificates.
        """
        return self._trust_store

    @property
    def sni_callback(self):
        """
        The callback function that will be called after the TLS Client
        Hello handshake message has been received by the TLS server when
        the TLS client specifies a server name indication, if any.
        """
        return self._sni_callback


class _BaseContext(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, configuration):
        """
        Create a new context object from a given TLS configuration.
        """

    @property
    @abstractmethod
    def configuration(self):
        """
        Returns the TLS configuration that was used to create the context.
        """


class ClientContext(_BaseContext):
    def wrap_socket(self, socket, server_hostname):
        """
        Wrap an existing Python socket object ``socket`` and return a
        ``TLSWrappedSocket`` object. ``socket`` must be a ``SOCK_STREAM``
        socket: all other socket types are unsupported.

        The returned SSL socket is tied to the context, its settings and
        certificates. The socket object originally passed to this method
        should not be used again: attempting to use it in any way will lead
        to undefined behaviour, especially across different TLS
        implementations. To get the original socket object back once it has
        been wrapped in TLS, see the ``unwrap`` method of the
        TLSWrappedSocket.

        The parameter ``server_hostname`` specifies the hostname of the
        service which we are connecting to. This allows a single server to
        host multiple SSL-based services with distinct certificates, quite
        similarly to HTTP virtual hosts. This is also used to validate the
        TLS certificate for the given hostname. If hostname validation is
        not desired, then pass ``None`` for this parameter. This parameter
        has no default value because opting-out of hostname validation is
        dangerous, and should not be the default behaviour.
        """
        buffer = self.wrap_buffers(server_hostname)
        return TLSWrappedSocket(socket, buffer)

    @abstractmethod
    def wrap_buffers(self, server_hostname):
        """
        Create an in-memory stream for TLS, using memory buffers to store
        incoming and outgoing ciphertext. The TLS routines will read
        received TLS data from one buffer, and write TLS data that needs to
        be emitted to another buffer.

        The implementation details of how this buffering works are up to
        the individual TLS implementation. This allows TLS libraries that
        have their own specialised support to continue to do so, while
        allowing those without to use whatever Python objects they see fit.

        The ``server_hostname`` parameter has the same meaning as in
        ``wrap_socket``.
        """


class ServerContext(_BaseContext):
    def wrap_socket(self, socket):
        """
        Wrap an existing Python socket object ``socket`` and return a
        ``TLSWrappedSocket`` object. ``socket`` must be a ``SOCK_STREAM``
        socket: all other socket types are unsupported.

        The returned SSL socket is tied to the context, its settings and
        certificates. The socket object originally passed to this method
        should not be used again: attempting to use it in any way will lead
        to undefined behaviour, especially across different TLS
        implementations. To get the original socket object back once it has
        been wrapped in TLS, see the ``unwrap`` method of the
        TLSWrappedSocket.
        """
        buffer = self.wrap_buffers()
        return TLSWrappedSocket(socket, buffer)

    @abstractmethod
    def wrap_buffers(self):
        """
        Create an in-memory stream for TLS, using memory buffers to store
        incoming and outgoing ciphertext. The TLS routines will read
        received TLS data from one buffer, and write TLS data that needs to
        be emitted to another buffer.

        The implementation details of how this buffering works are up to
        the individual TLS implementation. This allows TLS libraries that
        have their own specialised support to continue to do so, while
        allowing those without to use whatever Python objects they see fit.
        """


class TLSWrappedBuffer(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def read(self, amt):
        """
        Read up to ``amt`` bytes of data from the input buffer and return
        the result as a ``bytes`` instance.

        Once EOF is reached, all further calls to this method return the
        empty byte string ``b''``.

        May read "short": that is, fewer bytes may be returned than were
        requested.

        Raise ``WantReadError`` or ``WantWriteError`` if there is
        insufficient data in either the input or output buffer and the
        operation would have caused data to be written or read.

        May raise ``RaggedEOF`` if the connection has been closed without a
        graceful TLS shutdown. Whether this is an exception that should be
        ignored or not is up to the specific application.

        As at any time a re-negotiation is possible, a call to ``read()``
        can also cause write operations.
        """

    @abstractmethod
    def readinto(self, buffer, amt):
        """
        Read up to ``amt`` bytes of data from the input buffer into
        ``buffer``, which must be an object that implements the buffer
        protocol. Returns the number of bytes read.

        Once EOF is reached, all further calls to this method return the
        empty byte string ``b''``.

        Raises ``WantReadError`` or ``WantWriteError`` if there is
        insufficient data in either the input or output buffer and the
        operation would have caused data to be written or read.

        May read "short": that is, fewer bytes may be read than were
        requested.

        May raise ``RaggedEOF`` if the connection has been closed without a
        graceful TLS shutdown. Whether this is an exception that should be
        ignored or not is up to the specific application.

        As at any time a re-negotiation is possible, a call to
        ``readinto()`` can also cause write operations.
        """

    @abstractmethod
    def write(self, buf):
        """
        Write ``buf`` in encrypted form to the output buffer and return the
        number of bytes written. The ``buf`` argument must be an object
        supporting the buffer interface.

        Raise ``WantReadError`` or ``WantWriteError`` if there is
        insufficient data in either the input or output buffer and the
        operation would have caused data to be written or read. In either
        case, users should endeavour to resolve that situation and then
        re-call this method. When re-calling this method users *should*
        re-use the exact same ``buf`` object, as some backends require that
        the exact same buffer be used.

        This operation may write "short": that is, fewer bytes may be
        written than were in the buffer.

        As at any time a re-negotiation is possible, a call to ``write()``
        can also cause read operations.
        """

    @abstractmethod
    def do_handshake(self):
        """
        Performs the TLS handshake. Also performs certificate validation
        and hostname verification.
        """

    @abstractmethod
    def cipher(self):
        """
        Returns the CipherSuite entry for the cipher that has been
        negotiated on the connection. If no connection has been negotiated,
        returns ``None``. If the cipher negotiated is not defined in
        CipherSuite, returns the 16-bit integer representing that cipher
        directly.
        """

    @abstractmethod
    def negotiated_protocol(self):
        """
        Returns the protocol that was selected during the TLS handshake.
        This selection may have been made using ALPN, NPN, or some future
        negotiation mechanism.

        If the negotiated protocol is one of the protocols defined in the
        ``NextProtocol`` enum, the value from that enum will be returned.
        Otherwise, the raw bytestring of the negotiated protocol will be
        returned.

        If ``Context.set_inner_protocols()`` was not called, if the other
        party does not support protocol negotiation, if this socket does
        not support any of the peer's proposed protocols, or if the
        handshake has not happened yet, ``None`` is returned.
        """

    @property
    @abstractmethod
    def context(self):
        """
        The ``Context`` object this buffer is tied to.
        """

    @abstractproperty
    def negotiated_tls_version(self):
        """
        The version of TLS that has been negotiated on this connection.
        """

    @abstractmethod
    def shutdown(self):
        """
        Performs a clean TLS shut down. This should generally be used
        whenever possible to signal to the remote peer that the content is
        finished.
        """

    @abstractmethod
    def receive_from_network(self, data):
        """
        Receives some TLS data from the network and stores it in an
        internal buffer.

        If the internal buffer is overfull, this method will raise
        ``WantReadError`` and store no data. At this point, the user must
        call ``read`` or ``readinto`` to remove some data from the internal
        buffer before repeating this call.
        """

    @abstractmethod
    def peek_outgoing(self, amt):
        """
        Returns the next ``amt`` bytes of data that should be written to
        the network from the outgoing data buffer, without removing it from
        the internal buffer.
        """

    @abstractmethod
    def consume_outgoing(self, amt):
        """
        Discard the next ``amt`` bytes from the outgoing data buffer. This
        should be used when ``amt`` bytes have been sent on the network, to
        signal that the data no longer needs to be buffered.
        """


class TLSWrappedSocket(object):
    def do_handshake(self):
        """
        Performs the TLS handshake. Also performs certificate validation
        and hostname verification. This must be called after the socket has
        connected (either via ``connect`` or ``accept``), before any other
        operation is performed on the socket.
        """

    def cipher(self):
        """
        Returns the CipherSuite entry for the cipher that has been
        negotiated on the connection. If no connection has been negotiated,
        returns ``None``. If the cipher negotiated is not defined in
        CipherSuite, returns the 16-bit integer representing that cipher
        directly.
        """

    def negotiated_protocol(self):
        """
        Returns the protocol that was selected during the TLS handshake.
        This selection may have been made using ALPN, NPN, or some future
        negotiation mechanism.

        If the negotiated protocol is one of the protocols defined in the
        ``NextProtocol`` enum, the value from that enum will be returned.
        Otherwise, the raw bytestring of the negotiated protocol will be
        returned.

        If ``Context.set_inner_protocols()`` was not called, if the other
        party does not support protocol negotiation, if this socket does
        not support any of the peer's proposed protocols, or if the
        handshake has not happened yet, ``None`` is returned.
        """

    @property
    def context(self):
        """
        The ``Context`` object this socket is tied to.
        """

    def negotiated_tls_version(self):
        """
        The version of TLS that has been negotiated on this connection.
        """

    def unwrap(self):
        """
        Cleanly terminate the TLS connection on this wrapped socket. Once
        called, this ``TLSWrappedSocket`` can no longer be used to transmit
        data. Returns the socket that was wrapped with TLS.
        """


class CipherSuite(IntEnum):
    TLS_RSA_WITH_RC4_128_SHA = 0x0005
    TLS_RSA_WITH_IDEA_CBC_SHA = 0x0007
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000a
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f
    TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x0031
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
    TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x0037
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0x003f
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0041
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0043
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0045
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0x0069
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006b
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0084
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0086
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0088
    TLS_RSA_WITH_SEED_CBC_SHA = 0x0096
    TLS_DH_RSA_WITH_SEED_CBC_SHA = 0x0098
    TLS_DHE_RSA_WITH_SEED_CBC_SHA = 0x009a
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009e
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009f
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = 0x00a0
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = 0x00a1
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00ba
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00bc
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00be
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00c0
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00c2
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00c4
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA = 0xc002
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xc003
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0xc004
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xc005
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xc007
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xc008
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a
    TLS_ECDH_RSA_WITH_RC4_128_SHA = 0xc00c
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 0xc00d
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0xc00e
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xc00f
    TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xc011
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xc012
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc025
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc026
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xc029
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 0xc02a
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02d
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02e
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0xc031
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0xc032
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc072
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc073
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc074
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc075
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc076
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc077
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc078
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc079
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc07a
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc07b
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc07c
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc07d
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc07e
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc07f
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc086
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc087
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc088
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc089
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc08a
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc08b
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc08c
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc08d
    TLS_RSA_WITH_AES_128_CCM = 0xc09c
    TLS_RSA_WITH_AES_256_CCM = 0xc09d
    TLS_DHE_RSA_WITH_AES_128_CCM = 0xc09e
    TLS_DHE_RSA_WITH_AES_256_CCM = 0xc09f
    TLS_RSA_WITH_AES_128_CCM_8 = 0xc0a0
    TLS_RSA_WITH_AES_256_CCM_8 = 0xc0a1
    TLS_DHE_RSA_WITH_AES_128_CCM_8 = 0xc0a2
    TLS_DHE_RSA_WITH_AES_256_CCM_8 = 0xc0a3
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xc0ac
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 0xc0ad
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xc0ae
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0xc0af
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xccaa


DEFAULT_CIPHER_LIST = [
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
    CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
    CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
    CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
    CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
    CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA,
    CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
    CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
    CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
    CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
    CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
]


class NextProtocol(Enum):
    H2 = b'h2'
    H2C = b'h2c'
    HTTP1 = b'http/1.1'
    WEBRTC = b'webrtc'
    C_WEBRTC = b'c-webrtc'
    FTP = b'ftp'
    STUN = b'stun.nat-discovery'
    TURN = b'stun.turn'


class TLSVersion(Enum):
    MINIMUM_SUPPORTED = 'MINIMUM_SUPPORTED'
    SSLv2 = 'SSLv2'
    SSLv3 = 'SSLv3'
    TLSv1 = 'TLSv1'
    TLSv1_1 = 'TLSv1_1'
    TLSv1_2 = 'TLSv1_2'
    TLSv1_3 = 'TLSv1_3'
    MAXIMUM_SUPPORTED = 'MAXIMUM_SUPPORTED'


class TLSError(Exception):
    """
    The base exception for all TLS related errors from any backend.
    Catching this error should be sufficient to catch *all* TLS errors,
    regardless of what backend is used.
    """

class WantWriteError(TLSError):
    """
    A special signaling exception used only when non-blocking or
    buffer-only I/O is used. This error signals that the requested
    operation cannot complete until more data is written to the network,
    or until the output buffer is drained.

    This error is should only be raised when it is completely impossible
    to write any data. If a partial write is achievable then this should
    not be raised.
    """

class WantReadError(TLSError):
    """
    A special signaling exception used only when non-blocking or
    buffer-only I/O is used. This error signals that the requested
    operation cannot complete until more data is read from the network, or
    until more data is available in the input buffer.

    This error should only be raised when it is completely impossible to
    write any data. If a partial write is achievable then this should not
    be raised.
    """

class RaggedEOF(TLSError):
    """
    A special signaling exception used when a TLS connection has been
    closed gracelessly: that is, when a TLS CloseNotify was not received
    from the peer before the underlying TCP socket reached EOF. This is a
    so-called "ragged EOF".

    This exception is not guaranteed to be raised in the face of a ragged
    EOF: some implementations may not be able to detect or report the
    ragged EOF.

    This exception is not always a problem. Ragged EOFs are a concern only
    when protocols are vulnerable to length truncation attacks. Any
    protocol that can detect length truncation attacks at the application
    layer (e.g. HTTP/1.1 and HTTP/2) is not vulnerable to this kind of
    attack and so can ignore this exception.
    """


class Certificate(object):
    @classmethod
    def from_buffer(cls, buffer):
        """
        Creates a Certificate object from a byte buffer. This byte buffer
        may be either PEM-encoded or DER-encoded. If the buffer is PEM
        encoded it *must* begin with the standard PEM preamble (a series of
        dashes followed by the ASCII bytes "BEGIN CERTIFICATE" and another
        series of dashes). In the absence of that preamble, the
        implementation may assume that the certificate is DER-encoded
        instead.
        """
        raise NotImplementedError("Certificates from buffers not supported")

    @classmethod
    def from_file(cls, path):
        """
        Creates a Certificate object from a file on disk. This method may
        be a convenience method that wraps ``open`` and ``from_buffer``,
        but some TLS implementations may be able to provide more-secure or
        faster methods of loading certificates that do not involve Python
        code.
        """
        raise NotImplementedError("Certificates from files not supported")


class PrivateKey(object):
    @classmethod
    def from_buffer(cls, buffer, password):
        """
        Creates a PrivateKey object from a byte buffer. This byte buffer
        may be either PEM-encoded or DER-encoded. If the buffer is PEM
        encoded it *must* begin with the standard PEM preamble (a series of
        dashes followed by the ASCII bytes "BEGIN", the key type, and
        another series of dashes). In the absence of that preamble, the
        implementation may assume that the certificate is DER-encoded
        instead.

        The key may additionally be encrypted. If it is, the ``password``
        argument can be used to decrypt the key. The ``password`` argument
        may be a function to call to get the password for decrypting the
        private key. It will only be called if the private key is encrypted
        and a password is necessary. It will be called with no arguments,
        and it should return either bytes or bytearray containing the
        password. Alternatively a bytes, or bytearray value may be supplied
        directly as the password argument. It will be ignored if the
        private key is not encrypted and no password is needed.
        """
        raise NotImplementedError("Private Keys from buffers not supported")

    @classmethod
    def from_file(cls, path, password):
        """
        Creates a PrivateKey object from a file on disk. This method may
        be a convenience method that wraps ``open`` and ``from_buffer``,
        but some TLS implementations may be able to provide more-secure or
        faster methods of loading certificates that do not involve Python
        code.

        The ``password`` parameter behaves exactly as the equivalent
        parameter on ``from_buffer``.
        """
        raise NotImplementedError("Private Keys from buffers not supported")


class TrustStore(object):
    __metaclass__ = ABCMeta

    @classmethod
    def system(cls):
        """
        Returns a TrustStore object that represents the system trust
        database.
        """
        raise NotImplementedError("System trust store not supported")

    @classmethod
    def from_pem_file(cls, path):
        """
        Initializes a trust store from a single file full of PEMs.
        """
        raise NotImplementedError("Trust store from PEM not supported")


class Backend(object):
    """
    An object representing the collection of classes that implement the
    PEP 543 abstract TLS API for a specific TLS implementation.
    """
    __slots__ = (
        '_client_context', '_server_context', '_certificate',
        '_private_key', '_trust_store'
    )

    def __init__(self, client_context,
                       server_context,
                       certificate,
                       private_key,
                       trust_store):
        self._client_context = client_context
        self._server_context = server_context
        self._certificate = certificate
        self._private_key = private_key
        self._trust_store = trust_store

    @property
    def client_context(self):
        """
        The concrete implementation of the PEP 543 Client Context object,
        if this TLS backend supports being the client on a TLS connection.
        """
        return self._client_context

    @property
    def server_context(self):
        """
        The concrete implementation of the PEP 543 Server Context object,
        if this TLS backend supports being a server on a TLS connection.
        """
        return self._server_context

    @property
    def certificate(self):
        """
        The concrete implementation of the PEP 543 Certificate object used
        by this TLS backend.
        """
        return self._certificate

    @property
    def private_key(self):
        """
        The concrete implementation of the PEP 543 Private Key object used
        by this TLS backend.
        """
        return self._private_key

    @property
    def trust_store(self):
        """
        The concrete implementation of the PEP 543 TrustStore object used
        by this TLS backend.
        """
        return self._trust_store
