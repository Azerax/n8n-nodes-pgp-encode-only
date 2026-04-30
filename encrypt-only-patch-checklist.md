# PGP n8n Fork: Encrypt-Only Patch Checklist

## Objective

Reduce the fork to the minimum required for the Bridger/LexisNexis-style batch upload workflow:

```text
Input text or binary file
→ normalize recipient public key
→ encrypt using public key only
→ output .pgp binary
→ upload via SFTP
```

## Evidence from existing files

### `credentials/PgpCredentialsApi.credentials.ts`

Remove because not needed for encryption-only:

- `passphrase`, lines 10-19
- `private_key`, lines 74-93
- `privateURL`, lines 94-111

Keep:

- `keyMethod`, lines 20-35
- manual `public_key`, lines 36-55
- server `publicKeyFile`, lines 56-73

### `nodes/PgpNode/PgpNode.node.ts`

Remove because they add private-key/sign/decrypt/create paths:

- `PrivateKey` import, line 9
- `signText`, `signBinary`, `decryptText`, `decryptBinary`, `verifyText`, `verifyBinary`, `createPGPKeyPair`, lines 13-19
- Decrypt operation, lines 51-54
- Create operation, lines 59-62
- Create key UI, lines 65-180
- Encryption Options collection, lines 256-281
- Decryption Options collection, lines 282-357
- Create execution block, lines 385-438
- Private key loading block, lines 446-481
- Signing logic inside encrypt, lines 542-611
- Decrypt execution block, lines 623-760

Fix:

- Existing binary encryption uses `Buffer.from(item.binary[binaryPropertyName].data)` without specifying `base64`. n8n binary data is base64, so the patched code uses `Buffer.from(sourceBinary.data, 'base64')` before encryption.

### `nodes/PgpNode/utils/operations.ts`

Keep and simplify:

- `encryptText`
- `encryptBinary`

Remove:

- private-key parameters from encrypt functions
- `decryptText`
- `decryptBinary`
- `signText`
- `signBinary`
- `verifyText`
- `verifyBinary`
- `createPGPKeyPair`

## Patch checklist

- [x] Back up files before modifying
- [x] Replace credentials with public-key-only credentials
- [x] Replace node UI with encrypt-only UI
- [x] Remove private key and passphrase code paths
- [x] Remove create/decrypt/sign/verify code paths
- [x] Normalize public key before `openpgp.readKey()`
- [x] Force unsigned encryption only
- [x] Decode n8n binary input from base64 before encrypting
- [x] Output encrypted file as binary property `data` by default
- [x] Update node aliases
- [x] Update README
- [x] Update package metadata

## Apply

From the fork root:

```powershell
powershell -ExecutionPolicy Bypass -File .\apply-encrypt-only-patch.ps1
```

Then:

```powershell
pnpm install
pnpm build
pnpm pack
```

## n8n recommended node config

```text
Operation: Encrypt
Input Type: Binary
Binary Property Name: data
Output Binary Property Name: data
Compression Algorithm: Uncompressed
```
