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
    createPGPKeyPair,
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
                    {
                        name: 'Create',
                        value: 'create',
                    },
                ],
            },
            {
                displayName: 'User Name',
                name: 'senderName',
                type: 'string',
                default: '',
                placeholder: 'John Doe',
                hint: 'The owner of the key',
                description: 'Will be used in the file name if present',
                displayOptions: {
                    show: {
                        operation: ['create'],
                    },
                },
            },
            {
                displayName: 'User Email',
                name: 'senderEmail',
                type: 'string',
                default: '',
                placeholder: 'John.Doe@email.com',
                hint: "The owner's email",
                displayOptions: {
                    show: {
                        operation: ['create'],
                    },
                },
            },
            {
                displayName: 'Config',
                name: 'generateConfig',
                type: 'collection',
                default: {},
                displayOptions: {
                    show: {
                        operation: ['create'],
                    },
                },
                // eslint-disable-next-line n8n-nodes-base/node-param-collection-type-unsorted-items
                options: [
                    {
                        displayName: 'Passphrase',
                        name: 'passphrase',
                        type: 'string',
                        default: '',
                        typeOptions: {
                            password: true,
                        },
                        description:
                            "The passphrase used to encrypt the generated private key. If omitted or empty, the key won't be encrypted.",
                    },
                    {
                        displayName: 'RSA Bits',
                        name: 'rsaBits',
                        type: 'number',
                        default: 4096,
                        description: 'Number of bits for RSA keys',
                    },
                    {
                        displayName: 'Curve',
                        name: 'curve',
                        type: 'options',
                        default: 'curve25519Legacy',
                        description: 'Elliptic curve for ECC keys',
                        options: [
                            {
                                name: 'curve25519Legacy',
                                value: 'curve25519Legacy',
                            },
                            {
                                name: 'brainpoolP256r1',
                                value: 'brainpoolP256r1',
                            },
                            {
                                name: 'brainpoolP384r1',
                                value: 'brainpoolP384r1',
                            },
                            {
                                name: 'brainpoolP512r1',
                                value: 'brainpoolP512r1',
                            },
                        ],
                    },
                    {
                        displayName: 'Date',
                        name: 'date',
                        type: 'dateTime',
                        default: '',
                        description: 'Override the creation date of the key and the key signatures',
                    },
                    {
                        displayName: 'Key Expiration Time',
                        name: 'keyExpirationTime',
                        type: 'number',
                        default: 0,
                        hint: '0 (never expires)',
                        description: 'Number of seconds from the key creation time after which the key expires',
                    },
                    {
                        displayName: 'Format',
                        name: 'format',
                        type: 'options',
                        default: 'armored',
                        description: 'Format of the output keys',
                        options: [
                            { name: 'Armored', value: 'armored' },
                            { name: 'Binary', value: 'binary' },
                        ],
                    },
                    {
                        displayName: 'File Name',
                        name: 'fileOutName',
                        type: 'string',
                        placeholder: 'Default: <name | email | date>',
                        default: '',
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
                displayOptions: {
                    show: {
                        operation: ['encrypt', 'decrypt'],
                    },
                },
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
                displayName: 'Decryption Options',
                name: 'decryptionOptions',
                type: 'collection',
                default: {},
                options: [
                    {
                        displayName: 'Binary Property Name (Signature)',
                        name: 'binaryPropertyNameSignature',
                        type: 'string',
                        default: 'signature',
                        displayOptions: {
                            hide: {
                                '/inputType': ['text'],
                            },
                        },
                    },
                    {
                        displayName: 'Dettached Signature',
                        name: 'dettachedSignature',
                        type: 'string',
                        default: '',
                        displayOptions: {
                            hide: {
                                '/inputType': ['binary'],
                            },
                        },
                    },
                    {
                        displayName: 'File Extension',
                        name: 'fileExt',
                        type: 'string',
                        default: 'pgp',
                        displayOptions: {
                            hide: {
                                '/inputType': ['text'],
                            },
                        },
                    },
                    {
                        displayName: 'File Name',
                        name: 'fileName',
                        type: 'string',
                        default: '',
                        displayOptions: {
                            hide: {
                                '/inputType': ['text'],
                            },
                        },
                    },
                    {
                        displayName: 'Mime Type',
                        name: 'mimeType',
                        type: 'string',
                        default: 'application/octet-stream',
                        displayOptions: {
                            hide: {
                                '/inputType': ['text'],
                            },
                        },
                    },
                    {
                        displayName: 'Validate Signature',
                        name: 'validateSignature',
                        type: 'boolean',
                        default: true,
                        noDataExpression: true,
                    },
                ],
                displayOptions: {
                    show: {
                        inputType: ['text', 'binary'],
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
        let priKey: PrivateKey | undefined;
        let pubKey: Key | undefined;

        let signMessage: boolean;
        let validateSignature: boolean;
        let dettachSignature: boolean;

        let mimeType: string;
        let fileExt: string;
        let fileName: string;

        operation = this.getNodeParameter('operation', 0) as string;
        if (operation === 'create') {
            for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
                const userId: openpgp.UserID = {
                    name: (this.getNodeParameter('senderName', itemIndex, '') as string).trim(),
                    email: (this.getNodeParameter('senderEmail', itemIndex, '') as string).trim(),
                };
                const config: openpgp.KeyOptions & { format: 'armored' | 'binary' } = {
                    userIDs: userId,
                    passphrase: (this.getNodeParameter('generateConfig[passphrase]', itemIndex, '') as string).trim(),
                    rsaBits: this.getNodeParameter('generateConfig[rsaBits]', itemIndex, 4096) as number,
                    curve: this.getNodeParameter(
                        'generateConfig[curve]',
                        itemIndex,
                        'curve25519Legacy',
                    ) as openpgp.EllipticCurveName,
                    keyExpirationTime: this.getNodeParameter(
                        'generateConfig[keyExpirationTime]',
                        itemIndex,
                        0,
                    ) as number,
                    date: this.getNodeParameter('generateConfig[date]', itemIndex, Date.now()) as Date,
                    format: this.getNodeParameter('generateConfig[format]', itemIndex, 'armored') as
                        | 'armored'
                        | 'binary',
                };

                const generatedKeys = await createPGPKeyPair(config);
                if (generatedKeys === false) {
                    throw new NodeOperationError(
                        this.getNode(),
                        `Could not be generate keys with config:\n${JSON.stringify(config)}`,
                    );
                }

                const fileName = this.getNodeParameter(
                    'generateConfig[fileOutName]',
                    itemIndex,
                    userId.name || userId.email || config.date,
                ) as string;

                item = items[itemIndex];
                item.binary = {
                    private: {
                        data: Buffer.from(generatedKeys.privateKey).toString('base64'),
                        mimeType: 'application/pgp-encrypted',
                        fileName: `${fileName}-private.pgp`,
                    },
                    public: {
                        data: Buffer.from(generatedKeys.publicKey).toString('base64'),
                        mimeType: 'application/pgp-encrypted',
                        fileName: `${fileName}-public.pgp`,
                    },
                };
            }
            return this.prepareOutputData(items);
        } else {
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

                const pKey = (credentials.private_key as string)?.trim() || '';
                if (pKey !== '') {
                    if (credentials.passphrase) {
                        priKey = await openpgp.decryptKey({
                            privateKey: await openpgp.readPrivateKey({
                                armoredKey: pKey,
                            }),
                            passphrase: credentials.passphrase as string,
                        });
                    } else {
                        priKey = await openpgp.readPrivateKey({
                            armoredKey: pKey,
                        });
                    }
                } else {
                    priKey = undefined;
                }
            } catch {
                throw new NodeOperationError(this.getNode(), 'Private key is not valid');
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
                const pKey = (credentials.public_key as string)?.trim() || '';
                if (pKey !== '') {
                    pubKey = await openpgp.readKey({
                        armoredKey: pKey,
                    });
                } else {
                    pubKey = undefined;
                }
            } catch {
                throw new NodeOperationError(this.getNode(), 'Public key is not valid');
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
                            throw new NodeOperationError(
                                this.getNode(),
                                `binary "${binaryPropertyName}" is not defined`,
                            );
                        }
                    }

                    switch (operation) {
                        case 'encrypt':
                            if (pubKey === undefined) {
                                throw new NodeOperationError(
                                    this.getNode(),
                                    'Invalid credentials for operation: Missing public key',
                                );
                            }

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
                                    if (priKey === undefined) {
                                        throw new NodeOperationError(
                                            this.getNode(),
                                            'Invalid credentials for operation: missing private key',
                                        );
                                    }
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
                                    if (priKey === undefined) {
                                        throw new NodeOperationError(
                                            this.getNode(),
                                            'Invalid credentials for operation: Missing private key',
                                        );
                                    }
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
                            validateSignature = this.getNodeParameter(
                                'decryptionOptions[validateSignature]',
                                itemIndex,
                                true,
                            ) as boolean;
                            if (priKey == undefined) {
                                throw new NodeOperationError(
                                    this.getNode(),
                                    'Invalid credentials for operation: Missing Private Key',
                                );
                            }

                            if (inputType === 'text') {
                                signature = this.getNodeParameter(
                                    'decryptionOptions[dettachedSignature]',
                                    itemIndex,
                                    '',
                                ) as string;

                                const decrypted = await decryptText(
                                    message,
                                    priKey,
                                    validateSignature && !signature ? pubKey : undefined,
                                );
                                if (decrypted === false) {
                                    throw new NodeOperationError(this.getNode(), 'Message could not be decrypted');
                                }

                                if (validateSignature && signature) {
                                    if (pubKey === undefined) {
                                        throw new NodeOperationError(
                                            this.getNode(),
                                            'Invalid credentials for operation: Missing public key',
                                        );
                                    }
                                    const isVerifiedDecryptAndVerify = await verifyText(
                                        decrypted.data,
                                        signature,
                                        pubKey,
                                    );
                                    decrypted.verified = isVerifiedDecryptAndVerify;
                                }

                                item.json = {
                                    decrypted: decrypted.data,
                                    verified: decrypted.verified,
                                };
                            } else {
                                binaryPropertyNameSignature = (
                                    this.getNodeParameter(
                                        'decryptionOptions[binaryPropertyNameSignature]',
                                        itemIndex,
                                        '',
                                    ) as string
                                ).trim();
                                mimeType = (
                                    this.getNodeParameter(
                                        'decryptionOptions[mimeType]',
                                        itemIndex,
                                        'application/octet-stream',
                                    ) as string
                                ).trim();
                                fileName = (
                                    this.getNodeParameter(
                                        'decryptionOptions[fileName]',
                                        itemIndex,
                                        item.binary[binaryPropertyName].fileName,
                                    ) as string
                                ).trim();
                                fileExt = (
                                    this.getNodeParameter('decryptionOptions[fileExt]', itemIndex, 'pgp') as string
                                ).trim();

                                const binaryDataDecrypt = Buffer.from(
                                    item.binary[binaryPropertyName].data,
                                    'base64',
                                ).toString('utf-8');
                                let decryptedMessage = await decryptBinary(
                                    binaryDataDecrypt,
                                    priKey,
                                    validateSignature && !binaryPropertyNameSignature ? pubKey : undefined,
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

                                if (validateSignature && binaryPropertyNameSignature) {
                                    try {
                                        if (pubKey === undefined) {
                                            throw new NodeOperationError(
                                                this.getNode(),
                                                'Invalid credentials for operation: Missing public key',
                                            );
                                        }
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
                                    } catch {
                                        throw new NodeOperationError(this.getNode(), 'Could not verify signature.');
                                    }
                                }
                                item.binary = {
                                    decrypted: {
                                        data: Buffer.from(decryptedMessage.data).toString('binary'),
                                        mimeType: mimeType,
                                        fileName: `${fileName}.${fileExt}`,
                                    },
                                };
                            }
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
}
