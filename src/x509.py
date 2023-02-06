"""x509 signing/verification implementation.
"""

import base64, hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import datetime


class Signer:
    def __init__(self, secret_key):
        self.secret_key = secret_key
        self.certificate = self.derive(secret_key)

    @classmethod
    def create(self):
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        with open("private_x509.key", "wb") as pem_out:
            pem_out.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        return Signer(private_key)

    @classmethod
    def derive(self, private_key, subject_name="dsse_lib", issuer_name="dsse_lib", subject_alternative_name="dsse_lib", expiration=30):
        one_day = datetime.timedelta(1, 0, 0)
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
        ]))
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * expiration))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(subject_alternative_name)]
            ),
            critical=False
        )
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        certificate = builder.sign(
            private_key=private_key, algorithm=hashes.SHA256(),
        )

        with open("certificate.crt", 'wb') as crt_out:
            crt_out.write(certificate.public_bytes(encoding=serialization.Encoding.PEM))
        return certificate

    def sign(self, message: bytes) -> bytes:
        """Returns the signature of `message`."""
        artifact_signature = self.secret_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return artifact_signature

    def keyid(self) -> str:
        """Returns the base64-encoded certificate."""
        return Verifier(self.certificate).keyid()


class Verifier:
    def __init__(self, certificate):
        self.certificate = certificate

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Returns true if `message` was signed by `signature`."""
        try:
            public_key = self.certificate.public_key()
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except:
            return False

    def keyid(self) -> str:
        """Returns the base64-encoded certificate."""
        return base64.b64encode(self.certificate.public_bytes(encoding=serialization.Encoding.PEM)).decode()
