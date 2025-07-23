# Attested KMS

This is a wrapper over classic KMS that allows you to implicitly perform operations that support AWS Nitro Enclave attestation. That is, the result of a request, such as GenerateDataKeyPair, will be the same as in classic KMS. Attested KMS automatically adds an attestation document to supported operations and automatically decrypts the response.
