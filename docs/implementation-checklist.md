# AES-256-GCM Implementation Checklist

This checklist keeps the project focused on practical, testable cryptography learning.

## Core Flow

- [x] Define the encryption/decryption flow
- [x] Document confidentiality and integrity
- [x] Document nonce-handling requirements
- [ ] Expand input validation
- [ ] Add more negative-path tests
- [ ] Review error messages for safe handling

## Test Cases

| Case | Expected result |
|---|---|
| Valid plaintext → encrypt → decrypt | Original plaintext is recovered |
| Wrong key | Decryption fails |
| Modified ciphertext | Authentication fails |
| Invalid/empty input | Application handles it predictably |
| Reused nonce scenario | Clearly rejected/avoided by design |

## Development Habit

For each change:

1. Make one focused change.
2. Add or update a test when behavior changes.
3. Run the test suite.
4. Record the design decision in documentation.

> This is an educational project. Production cryptographic software should use mature, reviewed libraries and appropriate key-management practices.
