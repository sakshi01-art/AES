# AES-256-GCM Design Notes

## What the Project Demonstrates
The project uses AES-256-GCM as a learning example for authenticated encryption.

## Security Concepts
- **Confidentiality:** encrypted content should not reveal the original plaintext.
- **Integrity/authentication:** GCM provides an authentication tag so modified ciphertext can be detected.
- **Nonce handling:** each encryption operation must use a nonce correctly; nonce reuse with GCM must be avoided.
- **Key handling:** application keys should be generated, stored, and protected using appropriate mechanisms.

## Testing Priorities
Useful tests include:
- encrypt → decrypt round trip
- incorrect key rejection
- modified ciphertext detection
- invalid input handling

This repository is educational; production cryptographic systems should use well-reviewed libraries and secure key-management practices.
