# AES-GCM Learning Notes

## What AES-GCM Provides

AES-GCM combines AES encryption with authentication. In a correct implementation, the receiver can detect when authenticated ciphertext or associated data has been modified.

## Important Concepts

- **Key:** secret value used by the cipher.
- **Nonce/IV:** unique value supplied for each encryption operation under a key.
- **Ciphertext:** encrypted representation of plaintext.
- **Authentication tag:** integrity/authentication output checked during decryption.
- **AAD:** additional authenticated data that is protected from undetected modification but is not encrypted.

## Conceptual Flow

~~~text
Plaintext + Key + Unique Nonce + AAD
                ↓
             AES-GCM
                ↓
       Ciphertext + Tag
~~~

## Implementation Reminder

Cryptographic code should use a well-reviewed library and should not invent custom encryption primitives. Nonce handling, key storage, error handling, and dependency maintenance are security-critical.

This repository is an educational project, not a substitute for a production security review.