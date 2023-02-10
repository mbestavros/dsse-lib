"""Example usage of dsse-lib

SPDX-License-Identifier: Apache-2.0
"""

import base64, json, binascii

from src import dsse, ecdsa, x509

from os.path import basename, exists

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from securesystemslib import keys, metadata, signer
from securesystemslib.exceptions import UnsupportedAlgorithmError


payloadType = 'http://example.com/HelloWorld'
message = b"hello world!"

print("--- DSSE - ECDSA DEMO ---")
print()

signer_ecdsa = ecdsa.Signer.create()
verifier_ecdsa = ecdsa.Verifier(signer_ecdsa.public_key)
dsse_signature = dsse.Sign(payloadType, message, signer_ecdsa)

print("--- DSSE JSON ---")
print(dsse_signature)
print()

result = dsse.Verify(dsse_signature, [('mykey_ecdsa', verifier_ecdsa)])

print("--- Verification status ---")
print(result)

print()
print("--- DSSE - X509 DEMO ---")
print()

signer_x509 = x509.Signer.create()
verifier_x509 = x509.Verifier(signer_x509.certificate)
dsse_signature = dsse.Sign(payloadType, message, signer_x509)

print("--- DSSE JSON ---")
print(dsse_signature)
print()

result = dsse.Verify(dsse_signature, [('mykey_x509', verifier_x509)])

print("--- Verification status ---")
print(result)
print()

print("--- Certificate PEM ---")
dsse_signature_json = json.loads(dsse_signature)
certificate_b64 = dsse_signature_json["signatures"][0]["keyid"]

print(base64.b64decode(certificate_b64))

print("--- Generate DSSE with securesystemslib ---")

keypath = "private_ecdsa.key"
with open(keypath, "r") as f:
    key_pem_sslib = f.read()

with open(keypath, "rb") as f:
    key_pem = f.read()

try:
    private_key_sslib = keys.import_ecdsakey_from_private_pem(key_pem_sslib)
except UnsupportedAlgorithmError:
    print(f"Unable to read key file at {keypath}! Must be a PEM-encoded ECDSA private key.")

def sign_sslib(artifact):
    envelope_signer = signer.SSlibSigner(private_key_sslib)

    envelope = metadata.Envelope(payload=artifact, payload_type=payloadType, signatures=[])
    envelope.create_sig(signer=envelope_signer)
    return envelope.to_dict()

sslib_envelope = sign_sslib(message)
print(sslib_envelope)

print()
print("--- Verify securesystemslib DSSE with dsse-lib ---")

pubkey = load_pem_private_key(key_pem, None).public_key()
dsse_lib_verifier = ecdsa.Verifier(pubkey)

result = dsse.Verify(json.dumps(sslib_envelope).encode(), [('mykey_ecdsa', dsse_lib_verifier)])
print(result)

with open("test_data/runtime-policy-pubkey.pub", "rb") as f:
    pubkey = f.read()

pubkey = serialization.load_pem_public_key(pubkey)

with open("test_data/runtime-policy-test-signed.json", "rb") as f:
    policy = f.read()

with open("test_data/runtime-policy-test-signed-bad.json", "rb") as f:
    policy_bad = f.read()

payloadType = 'application/vnd.keylime+json'

verifier_ecdsa = ecdsa.Verifier(pubkey)

result = dsse.Verify(policy_bad, [('mykey_ecdsa', verifier_ecdsa)])

print("--- Verification status ---")
print(result)
