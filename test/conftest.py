import datetime
import glob
import os.path
import shutil
import tempfile

import pytest

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization


ONE_DAY = datetime.timedelta(1, 0, 0)

TEMPDIR = None


def cert_and_key_by_name(name):
    """
    Given the name of a cert and key, returns a dictionary for use in a
    fixture.
    """
    cert = os.path.join(TEMPDIR, '{}.crt'.format(name))
    key = os.path.join(TEMPDIR, '{}.key'.format(name))
    return {'cert': cert, 'key': key}


def build_ca_cert(dirname):
    """
    The first step is building our certificate authority. This certificate
    authority is self-signed, and is used as the trust root for all other
    certificates we build.

    This method returns a dictionary containing four keys: 'cert', 'key',
    'certpath', and 'keypath. The 'cert' key points to a cryptography
    Certificate object, the 'key' object points to a cryptography PrivateKey
    object, the 'certpath' provides the path to a PEM containing the cert, and
    the 'keypath' provides the path to a PEM containing the key. It also writes
    out a certificate to 'cacert.crt' to the directory given.
    """
    keypath = os.path.join(dirname, 'ca.key')
    with open(keypath, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'PEP 543 Test CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Python Hyper Project'),
    ])

    # Now we need to build the CA. This includes a bunch of hard-coded nonsense
    # that mostly we shouldn't have to worry about. This first section is just
    # general setup.
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(ca_name)
    builder = builder.issuer_name(ca_name)
    builder = builder.not_valid_before(datetime.datetime.today() - ONE_DAY)
    builder = builder.not_valid_after(
        datetime.datetime.today() + (30 * ONE_DAY)
    )
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(private_key.public_key())

    # Ok, here we do some CA specific stuff. Specifically, we set this as a CA,
    # configure the authority and subject key identifiers to point to our own
    # key, set the key usage to allow us to sign other certs but otherwise to
    # not be able to do anything.
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=1), critical=True,
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            private_key.public_key()
        ), critical=False
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True
    )

    # Ok, sign the cert.
    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # We want to write the certificate out.
    certpath = os.path.join(dirname, 'ca.crt')
    with open(certpath, 'wb') as certfile:
        certfile.write(certificate.public_bytes(serialization.Encoding.PEM))

    return {
        'cert': certificate,
        'key': private_key,
        'certpath': certpath,
        'keypath': keypath,
    }


def build_intermediate_cert(dirname, ca_cert, ca_key):
    """
    Given the information for a parent CA, builds an intermediate certificate.
    This certificate is signed by the parent CA, and is used as an intermediary
    certificate for all our tests to validate that libraries can correctly
    handle intermediate certs for both clients and servers.

    This method returns a dictionary containing four keys: 'cert', 'key',
    'certpath', and 'keypath. The 'cert' key points to a cryptography
    Certificate object, the 'key' object points to a cryptography PrivateKey
    object, the 'certpath' provides the path to a PEM containing the cert, and
    the 'keypath' provides the path to a PEM containing the key. It also writes
    out a certificate to 'intermediate.crt' to the directory given.
    """
    keypath = os.path.join(dirname, 'intermediate.key')
    with open(keypath, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    ca_name = x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME, u'PEP 543 Intermediate Test CA'
        ),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Python Hyper Project'),
    ])

    # Now we need to build the CA. This includes a bunch of hard-coded nonsense
    # that mostly we shouldn't have to worry about. This first section is just
    # general setup. This cert lives slightly less long than the parent.
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(ca_name)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.not_valid_before(datetime.datetime.today() - ONE_DAY)
    builder = builder.not_valid_after(
        datetime.datetime.today() + (25 * ONE_DAY)
    )
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(private_key.public_key())

    # Ok, here we do some intermediate specific stuff. Specifically, we set
    # this as a CA, configure the authority key identifier to point to our
    # parent, our subject key identifier to point to our own key, and set the
    # key usage to allow us to sign other certs but otherwise to not be able to
    # do anything.
    issuer_ski = ca_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True,
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            issuer_ski
        ), critical=False
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True
    )

    # Ok, sign the cert.
    certificate = builder.sign(
        private_key=ca_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # We want to write the certificate out.
    certpath = os.path.join(dirname, 'intermediate.crt')
    with open(certpath, 'wb') as certfile:
        certfile.write(certificate.public_bytes(serialization.Encoding.PEM))

    return {
        'cert': certificate,
        'key': private_key,
        'certpath': certpath,
        'keypath': keypath,
    }


def build_leaf_certificate(dirname,
                           keyname,
                           certname,
                           common_name,
                           subject_alt_names,
                           ca_cert,
                           ca_key):
    """
    Builds a single leaf certificate based on a number of parameters.

    This method returns a dictionary containing four keys: 'cert', 'key',
    'certpath', and 'keypath. The 'cert' key points to a cryptography
    Certificate object, the 'key' object points to a cryptography PrivateKey
    object, the 'certpath' provides the path to a PEM containing the cert, and
    the 'keypath' provides the path to a PEM containing the key. It also writes
    out a certificate to 'certname' to the directory given.
    """
    keypath = os.path.join(dirname, keyname)
    with open(keypath, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Python Hyper Project'),
    ])

    # Now we need to build the CA. This includes a bunch of hard-coded nonsense
    # that mostly we shouldn't have to worry about. This first section is just
    # general setup. This cert lives slightly less long than the parent.
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.not_valid_before(datetime.datetime.today() - ONE_DAY)
    builder = builder.not_valid_after(
        datetime.datetime.today() + (20 * ONE_DAY)
    )
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(private_key.public_key())

    # Ok, here we do some leaf specific stuff. Specifically, we set this as not
    # a CA, configure the authority key identifier to point to our parent, our
    # subject key identifier to point to our own key, and set the key usage to
    # key usage to only do stuff that makes sense for leaf certs. We also set
    # the subject alternative name field to the provided names, and set
    # extended key usage to allow both server and client authentication.
    issuer_ski = ca_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            issuer_ski
        ), critical=False
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
        ),
        critical=False,
    )
    if subject_alt_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(subject_alt_names),
            critical=False
        )

    # Ok, sign the cert.
    certificate = builder.sign(
        private_key=ca_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # We want to write the certificate out. We also want to write out the
    # intermediate that signed it.
    certpath = os.path.join(dirname, certname)
    with open(certpath, 'wb') as certfile:
        certfile.write(certificate.public_bytes(serialization.Encoding.PEM))
        certfile.write(b'\n')
        certfile.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    return {
        'cert': certificate,
        'key': private_key,
        'certpath': certpath,
        'keypath': keypath,
    }


@pytest.fixture(autouse=True)
def cert_directory():
    """
    Provides a directory of certificates that are used to run the tests. By
    building these certificates each time we run the tests, we slow the test
    execution down quite substantially, but in return we get to ensure that the
    certificates are always in-date and valid.

    One thing this does *not* do is generate the keys each time. This is
    because keygen is the slowest and most CPU-intensive part of this process,
    and there is simply no need to forcibly repeat that process on a regular
    basis.
    """
    # Begin by creating our temporary directory and copying all our keys into
    # it.
    tempdir = tempfile.mkdtemp()
    keys = glob.glob('keys/*.key')
    for key in keys:
        shutil.copy(key, tempdir)

    # Build our root and intermediate CA
    ca_data = build_ca_cert(tempdir)
    intermediate_data = build_intermediate_cert(
        tempdir, ca_data['cert'], ca_data['key']
    )

    # Ok, build our leaves. We need one client cert and one root cert, with the
    # root cert being valid for localhost.
    client_san = x509.SubjectAlternativeName(
        [x509.RFC822Name(u'pep543@python-hyper.org')]
    )
    server_san = x509.SubjectAlternativeName(
        [x509.DNSName(u'localhost')]
    )
    build_leaf_certificate(
        tempdir,
        'client.key',
        'client.crt',
        u'PEP 543 Client Certificate',
        client_san,
        intermediate_data['cert'],
        intermediate_data['key']
    )
    build_leaf_certificate(
        tempdir,
        'server.key',
        'server.crt',
        u'localhost',
        server_san,
        intermediate_data['cert'],
        intermediate_data['key']
    )

    # Ok, we've set up. Let the tests run.
    global TEMPDIR
    TEMPDIR = tempdir
    yield

    # To cleanup, blow away the temporary directory.
    shutil.rmtree(tempdir)


@pytest.fixture
def client_cert():
    """
    A fixture that returns a dictionary containing the cert and key for the
    client.
    """
    return cert_and_key_by_name('client')


@pytest.fixture
def server_cert():
    """
    A fixture that returns a dictionary containing the cert and key for the
    server.
    """
    return cert_and_key_by_name('server')


@pytest.fixture
def ca_cert():
    """
    A fixture that returns a dictionary containing the cert and key for the
    CA.
    """
    return cert_and_key_by_name('ca')
