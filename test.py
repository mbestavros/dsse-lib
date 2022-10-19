import ecdsa, signing_spec

signer = ecdsa.Signer.create()

verifier = ecdsa.Verifier(signer.public_key)
payloadType = 'http://example.com/HelloWorld'

message = b"hello world!"


signature_json = signing_spec.Sign(payloadType, message, signer)

print(signature_json)

result = signing_spec.Verify(signature_json, [('mykey', verifier)])

print(result)
