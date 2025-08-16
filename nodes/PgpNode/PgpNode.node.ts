import {
    IExecuteFunctions,
    INodeExecutionData,
    INodeType,
    INodeTypeDescription,
    NodeOperationError,
} from 'n8n-workflow';
import * as openpgp from 'openpgp';
import { PrivateKey, Key } from 'openpgp';
import {
    encryptText,
    encryptBinary,
    signText,
    signBinary,
    decryptText,
    decryptBinary,
    verifyText,
    verifyBinary,
} from './utils/operations';
import { DataCompressor } from './utils/DataCompressor';

export class PgpNode implements INodeType {
    description: INodeTypeDescription = {
        displayName: 'PGP',
        name: 'pgpNode',
        icon: 'file:key.svg',
        group: ['transform'],
        version: 1,
        description: 'PGP Node',
        defaults: {
            name: 'PGP',
        },
        inputs: ['main'],
        outputs: ['main'],
        credentials: [
            {
                name: 'pgpCredentialsApi',
                required: false,
            },
        ],
        properties: [
            {
                displayName: 'Operation',
                name: 'operation',
                type: 'options',
                noDataExpression: true,
                default: 'encrypt',
                required: true,
                options: [
                    {
                        name: 'Decrypt',
                        value: 'decrypt',
                    },
                    {
                        name: 'Encrypt',
                        value: 'encrypt',
                    },
                ],
            },
            {
                displayName: 'Input Type',
                name: 'inputType',
                type: 'options',
                options: [
                    {
                        name: 'Text',
                        value: 'text',
                    },
                    {
                        name: 'Binary',
                        value: 'binary',
                    },
                ],
                default: 'text',
                description: 'Choose the type of input parameter',
            },
            {
                displayName: 'Compression Algorithm',
                name: 'compressionAlgorithm',
                type: 'options',
                options: [
                    {
                        name: 'Uncompressed',
                        value: 'uncompressed',
                    },
                    {
                        name: 'Zip',
                        value: 'zip',
                    },
                    {
                        name: 'Zlib',
                        value: 'zlib',
                    },
                ],
                default: 'uncompressed',
                description: 'Choose the compression algorithm',
                displayOptions: {
                    show: {
                        operation: ['encrypt', 'decrypt'],
                        inputType: ['binary'],
                    },
                },
            },
            {
                displayName: 'Message',
                name: 'message',
                type: 'string',
                default: '',
                placeholder: 'Message',
                description: 'The message text',
                displayOptions: {
                    show: {
                        inputType: ['text'],
                    },
                },
            },
            {
                displayName: 'Binary Property Name',
                name: 'binaryPropertyName',
                type: 'string',
                displayOptions: {
                    show: {
                        inputType: ['binary'],
                    },
                },
                default: 'message',
                description: 'Name of the binary property to process',
            },
            {
                displayName: 'Binary Property Name (Signature)',
                name: 'binaryPropertyNameSignature',
                type: 'string',
                default: 'signature',
                displayOptions: {
                    show: {
                        inputType: ['binary'],
                        operation: ['verify', 'decrypt'],
                        signatureIsDettached: [true],
                    },
                },
            },
            {
                displayName: 'Encryption Options',
                name: 'encryptionOptions',
                type: 'collection',
                default: {},
                options: [
                    {
                        displayName: 'Dettach Signature',
                        name: 'dettachSignature',
                        type: 'boolean',
                        default: false,
                    },
                    {
                        displayName: 'Sign Message',
                        name: 'signMessage',
                        type: 'boolean',
                        default: true,
                    },
                ],
                displayOptions: {
                    show: {
                        inputType: ['text', 'binary'],
                        operation: ['encrypt'],
                    },
                },
            },
            {
                displayName: 'Dettached Signature',
                name: 'dettachedSignature',
                type: 'string',
                default: '',
                displayOptions: {
                    show: {
                        operation: ['decrypt'],
                        inputType: ['text'],
                        signatureIsDettached: [true],
                    },
                },
            },
            {
                displayName: 'Validate Signature',
                name: 'validateSignature',
                type: 'boolean',
                default: true,
                noDataExpression: true,
                displayOptions: {
                    show: {
                        operation: ['decrypt'],
                    },
                },
            },
            {
                displayName: 'Dettached Signature',
                name: 'signatureIsDettached',
                type: 'boolean',
                default: false,
                noDataExpression: true,
                displayOptions: {
                    show: {
                        operation: ['decrypt'],
                    },
                },
            },
        ],
    };

    async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
        const items = this.getInputData();

        let item: INodeExecutionData;
        let operation: string;
        let signature: string;
        let inputType: string;
        let message: string;
        let binaryPropertyName: string;
        let binaryPropertyNameSignature: string;
        let compressionAlgorithm: string;

        let credentials;
        let priKey: PrivateKey;
        let pubKey: Key;

        let dettachSignature: boolean;
        let signMessage: boolean;
        let validateSignature: boolean;
        let isSignatureDettached: boolean;

        credentials = await this.getCredentials('pgpCredentialsApi');

        try {
            if (credentials.keyMethod === 'server') {
                let privateUrl = credentials.privateURL as string;

                if (privateUrl !== '') {
                    credentials.private_key = await this.helpers.request({
                        method: 'GET',
                        url: privateUrl,
                    });
                }
            }

            if (credentials.passphrase) {
                priKey = await openpgp.decryptKey({
                    privateKey: await openpgp.readPrivateKey({
                        armoredKey: (credentials.private_key as string).trim(),
                    }),
                    passphrase: credentials.passphrase as string,
                });
            } else {
                priKey = await openpgp.readPrivateKey({
                    armoredKey: (credentials.private_key as string).trim(),
                });
            }
        } catch {
            throw new NodeOperationError(this.getNode(), 'private key is not valid');
        }

        try {
            if (credentials.keyMethod === 'server') {
                let publicUrl = credentials.publicKeyFile as string;

                if (publicUrl !== '') {
                    credentials.public_key = await this.helpers.request({
                        method: 'GET',
                        url: publicUrl,
                    });
                }
            }
            pubKey = await openpgp.readKey({
                armoredKey: (credentials.public_key as string).trim(),
            });
        } catch {
            throw new NodeOperationError(this.getNode(), 'public key is not valid');
        }

        for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
            try {
                operation = this.getNodeParameter('operation', itemIndex) as string;
                inputType = this.getNodeParameter('inputType', itemIndex) as string;
                compressionAlgorithm = 'uncompressed';
                if (inputType === 'text') {
                    message = this.getNodeParameter('message', itemIndex) as string;
                    binaryPropertyName = '';
                } else {
                    message = '';
                    binaryPropertyName = this.getNodeParameter('binaryPropertyName', itemIndex) as string;
                    if (operation === 'encrypt' || operation === 'decrypt') {
                        compressionAlgorithm = this.getNodeParameter('compressionAlgorithm', itemIndex) as string;
                    }
                }

                item = items[itemIndex];
                if (inputType === 'text') {
                    item.binary = {};
                } else {
                    item.json = {};
                    if (!item.binary) {
                        throw new NodeOperationError(this.getNode(), 'binary is missing');
                    }

                    if (!item.binary[binaryPropertyName]) {
                        throw new NodeOperationError(this.getNode(), `binary "${binaryPropertyName}" is not defined`);
                    }
                }

                switch (operation) {
                    case 'encrypt':
                        dettachSignature = this.getNodeParameter(
                            'encryptionOptions[dettachSignature]',
                            itemIndex,
                            false,
                        ) as boolean;
                        signMessage = this.getNodeParameter(
                            'encryptionOptions[signMessage]',
                            itemIndex,
                            true,
                        ) as boolean;

                        if (inputType === 'text') {
                            item.json = {
                                encrypted: await encryptText(
                                    message,
                                    pubKey,
                                    signMessage && !dettachSignature ? priKey : undefined,
                                ),
                            };
                            if (dettachSignature && signMessage) {
                                item.json.signature = await signText(message, priKey);
                            }
                        } else {
                            let binaryDataUncompressed = Buffer.from(item.binary[binaryPropertyName].data);
                            let binaryDataCompressed;
                            if (compressionAlgorithm !== 'uncompressed') {
                                binaryDataCompressed = DataCompressor.compress(
                                    binaryDataUncompressed,
                                    compressionAlgorithm,
                                );
                            } else {
                                binaryDataCompressed = binaryDataUncompressed;
                            }
                            const encryptedMessage = await encryptBinary(
                                binaryDataCompressed,
                                pubKey,
                                signMessage && !dettachSignature ? priKey : undefined,
                            );

                            if (dettachSignature && signMessage) {
                                const signatureEncryptAndSign = (await signBinary(
                                    binaryDataUncompressed,
                                    priKey,
                                )) as string;

                                item.binary = {
                                    message: {
                                        data: Buffer.from(encryptedMessage).toString('base64'),
                                        mimeType: 'application/pgp-encrypted',
                                        fileName: `${item.binary[binaryPropertyName].fileName}.pgp`,
                                    },
                                    signature: {
                                        data: Buffer.from(signatureEncryptAndSign).toString('base64'),
                                        mimeType: 'application/pgp-signature',
                                        fileExtension: 'sig',
                                        fileName: `${item.binary[binaryPropertyName].fileName}.sig`,
                                    },
                                };
                            } else {
                                item.binary = {
                                    message: {
                                        data: Buffer.from(encryptedMessage).toString('base64'),
                                        mimeType: 'application/pgp-encrypted',
                                        fileName: `${item.binary[binaryPropertyName].fileName}.pgp`,
                                    },
                                };
                            }
                        }
                        break;
                    case 'decrypt':
                        isSignatureDettached = this.getNodeParameter(
                            'signatureIsDettached',
                            itemIndex,
                            false,
                        ) as boolean;
                        validateSignature = this.getNodeParameter('validateSignature', itemIndex, true) as boolean;

                        if (inputType === 'text') {
                            const decrypted = await decryptText(
                                message,
                                priKey,
                                validateSignature && !isSignatureDettached ? pubKey : undefined,
                            );
                            if (decrypted === false) {
                                throw new NodeOperationError(this.getNode(), 'Message could not be decrypted');
                            }

                            if (validateSignature && isSignatureDettached) {
                                signature = this.getNodeParameter('dettachedSignature', itemIndex, '') as string;
                                if (signature !== '') {
                                    const isVerifiedDecryptAndVerify = await verifyText(
                                        decrypted.data,
                                        signature,
                                        pubKey,
                                    );
                                    decrypted.verified = isVerifiedDecryptAndVerify;
                                }
                            }

                            item.json = {
                                decrypted: decrypted.data,
                                verified: decrypted.verified,
                            };
                        } else {
                            const binaryDataDecrypt = Buffer.from(
                                item.binary[binaryPropertyName].data,
                                'base64',
                            ).toString('utf-8');
                            let decryptedMessage = await decryptBinary(
                                binaryDataDecrypt,
                                priKey,
                                validateSignature && !isSignatureDettached ? pubKey : undefined,
                            );
                            if (decryptedMessage === false) {
                                throw new NodeOperationError(this.getNode(), 'Message could not be decrypted');
                            }

                            if (compressionAlgorithm !== 'uncompressed') {
                                try {
                                    decryptedMessage.data = DataCompressor.uncompress(
                                        decryptedMessage.data,
                                        compressionAlgorithm,
                                    );
                                } catch {
                                    throw new NodeOperationError(
                                        this.getNode(),
                                        'Message could not be uncompressed. Please check your compression algorithm.',
                                    );
                                }
                            }

                            item.json = {
                                verified: decryptedMessage.verified,
                            };

                            if (validateSignature && isSignatureDettached) {
                                try {
                                    binaryPropertyNameSignature = this.getNodeParameter(
                                        'binaryPropertyNameSignature',
                                        itemIndex,
                                        '',
                                    ) as string;
                                    if (binaryPropertyNameSignature !== '') {
                                        const binarySignatureDataDecryptAndVerify = Buffer.from(
                                            item.binary[binaryPropertyNameSignature].data,
                                            'base64',
                                        ).toString('utf-8');
                                        const isVerifiedDecryptAndVerified = await verifyBinary(
                                            decryptedMessage.data,
                                            binarySignatureDataDecryptAndVerify,
                                            pubKey,
                                        );
                                        item.json = {
                                            verified: isVerifiedDecryptAndVerified,
                                        };
                                    }
                                } catch {
                                    throw new NodeOperationError(this.getNode(), 'Could not verify signature.');
                                }
                            }
                            item.binary = {
                                decrypted: {
                                    data: Buffer.from(decryptedMessage.data).toString('utf-8'),
                                    mimeType: 'application/octet-stream',
                                    fileName: `${item.binary[binaryPropertyName].fileName}.pgp`,
                                },
                            };
                        }
                        break;
                    case 'sign':
                        if (inputType === 'text') {
                            item.json = {
                                message: message,
                                signature: await signText(message, priKey),
                            };
                        } else {
                            const binaryDataSign = Buffer.from(item.binary[binaryPropertyName].data);
                            const signature = (await signBinary(binaryDataSign, priKey)) as string;

                            item.binary = {
                                message: {
                                    data: Buffer.from(signature).toString('base64'),
                                    mimeType: 'application/pgp-signature',
                                    fileExtension: 'pgp',
                                    fileName: `${item.binary[binaryPropertyName].fileName}.pgp`,
                                },
                                signature: {
                                    data: Buffer.from(signature).toString('base64'),
                                    mimeType: 'application/pgp-signature',
                                    fileExtension: 'sig',
                                    fileName: item.binary[binaryPropertyName].fileName + '.sig',
                                },
                            };
                        }
                        break;
                    case 'verify':
                        // if (inputType === 'text') {
                        //     signature = this.getNodeParameter('signature', itemIndex) as string;
                        //     const isVerified = await verifyText(message, signature, pubKey);

                        //     item.json = {
                        //         verified: isVerified,
                        //     };
                        // } else {
                        //     binaryPropertyNameSignature = this.getNodeParameter(
                        //         'binaryPropertyNameSignature',
                        //         itemIndex,
                        //     ) as string | undefined;
                        //     const binarySignatureDataVerify = atob(item.binary[binaryPropertyNameSignature].data);
                        //     const binaryDataVerify = BinaryUtils.base64ToUint8Array(
                        //         item.binary[binaryPropertyName].data,
                        //     );
                        //     const isVerified = await verifyBinary(binaryDataVerify, binarySignatureDataVerify, pubKey);

                        //     item.json = {
                        //         verified: isVerified,
                        //     };
                        //     item.binary = {};
                        // }
                        break;
                }
            } catch (error) {
                if (this.continueOnFail()) {
                    items.push({
                        json: this.getInputData(itemIndex)[0].json,
                        error,
                        pairedItem: itemIndex,
                    });
                } else {
                    if (error.context) {
                        error.context.itemIndex = itemIndex;
                        throw error;
                    }
                    throw new NodeOperationError(this.getNode(), error, {
                        itemIndex,
                    });
                }
            }
        }

        return this.prepareOutputData(items);
    }
}
