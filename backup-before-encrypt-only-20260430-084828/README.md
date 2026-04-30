# n8n PGP Encrypt Only Node

This fork is intentionally reduced to one job: encrypt text or binary data with a recipient PGP public key.

## Why this fork exists

The original node supported creating keys, decrypting, signing, verifying, private keys, passphrases, and detached signatures. For batch upload workflows such as encrypting a CSV before SFTP upload, those options add unnecessary failure points.

This fork removes those paths and keeps only public-key encryption.

## Supported

- Encrypt text
- Encrypt binary files
- Manual recipient public key
- Recipient public key from URL
- Optional pre-encryption binary compression
- Encrypted binary output as `data` for SFTP upload nodes

## Not supported

- Private keys
- Passphrases
- Decryption
- Signing
- Signature verification
- Detached signatures
- Key generation

## Recommended binary setup

For downloaded files, use:

```text
Input Type: Binary
Binary Property Name: data
Output Binary Property Name: data
Compression Algorithm: Uncompressed
```

Then point your SFTP node at binary property:

```text
data
```

## Public key handling

The node normalizes common public-key formatting problems before parsing:

- literal `\n` from JSON/env copy-paste
- Windows CRLF line endings
- accidental surrounding quotes
- extra text around the armored public key block
- common missing blank line after the BEGIN header

The key must still be a valid encryption-capable PGP public key. This node does not bypass OpenPGP cryptographic requirements; it only removes unnecessary private-key/signing/decryption logic.
