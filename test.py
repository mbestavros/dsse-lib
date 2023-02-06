"""Example usage of dsse-lib

SPDX-License-Identifier: Apache-2.0
"""

import base64, json

from src import dsse, ecdsa, x509

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
