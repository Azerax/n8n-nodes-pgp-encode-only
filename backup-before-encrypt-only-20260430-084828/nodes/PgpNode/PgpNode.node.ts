import {
    IExecuteFunctions,
    INodeExecutionData,
    INodeType,
    INodeTypeDescription,
    NodeOperationError,
} from 'n8n-workflow';
import * as openpgp from 'openpgp';
import { Key } from 'openpgp';
import { encryptText, encryptBinary } from './utils/operations';
import { DataCompressor } from './utils/DataCompressor';

function normalizePublicKey(input: string): string {
    let key = (input || '').trim();

    // If the key was copied through JSON/env vars, convert literal escaped newlines.
    key = key
        .replace(/\\r\\n/g, '\n')
        .replace(/\\n/g, '\n')
        .replace(/\r\n/g, '\n')
        .replace(/\r/g, '\n');

    // Remove accidental surrounding quotes from copy/paste or JSON values.
    if ((key.startsWith('"') && key.endsWith('"')) || (key.startsWith("'") && key.endsWith("'"))) {
        key = key.slice(1, -1).trim();
    }

    // If extra text surrounds the key, extract only the armored public key block.
    const begin = key.indexOf('-----BEGIN PGP PUBLIC KEY BLOCK-----');
    const endMarker = '-----END PGP PUBLIC KEY BLOCK-----';
    const end = key.indexOf(endMarker);
    if (begin >= 0 && end >= begin) {
        key = key.slice(begin, end + endMarker.length).trim();
    }

    // OpenPGP armor requires a blank line between armor headers and body.
    // Do not attempt to rewrite full armor, just fix the common missing-blank-line case.
    key = key.replace(
        /-----BEGIN PGP PUBLIC KEY BLOCK-----\n(?!\n)(?![A-Za-z0-9-]+:)/,
        '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n',
    );

    return `${key}\n`;
}

async function readRecipientPublicKey(context: IExecuteFunctions): Promise<Key> {
    const credentials = await context.getCredentials('pgpCredentialsApi');
    let publicKeyText = '';

    if (credentials.keyMethod === 'server') {
        const publicUrl = ((credentials.publicKeyFile as string) || '').trim();
        if (!publicUrl) {
            throw new NodeOperationError(context.getNode(), 'Missing Public Key URL');
        }
        publicKeyText = (await context.helpers.request({
            method: 'GET',
            url: publicUrl,
        })) as string;
    } else {
        publicKeyText = ((credentials.public_key as string) || '').trim();
    }

    const normalizedKey = normalizePublicKey(publicKeyText);
    if (!normalizedKey.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
        throw new NodeOperationError(context.getNode(), 'Public key is missing the BEGIN PGP PUBLIC KEY BLOCK header');
    }

    try {
        return await openpgp.readKey({ armoredKey: normalizedKey });
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new NodeOperationError(context.getNode(), `Public key could not be parsed after normalization: ${message}`);
    }
}

export class PgpNode implements INodeType {
    description: INodeTypeDescription = {
        displayName: 'PGP Encrypt Only',
        name: 'pgpNode',
        icon: 'file:key.svg',
        group: ['transform'],
        version: 1,
        description: 'Encrypt text or binary data with a recipient PGP public key. No private key, passphrase, signing, decrypting, or key generation.',
        defaults: {
            name: 'PGP Encrypt Only',
        },
        inputs: ['main'],
        outputs: ['main'],
        credentials: [
            {
                name: 'pgpCredentialsApi',
                required: true,
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
                default: 'binary',
                description: 'Choose whether to encrypt text from the node field or binary data from the incoming item.',
            },
            {
                displayName: 'Message',
                name: 'message',
                type: 'string',
                default: '',
                placeholder: 'Message',
                description: 'Text to encrypt.',
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
                default: 'data',
                description: 'Name of the incoming binary property to encrypt. n8n file download nodes commonly use data.',
            },
            {
                displayName: 'Output Binary Property Name',
                name: 'outputBinaryPropertyName',
                type: 'string',
                displayOptions: {
                    show: {
                        inputType: ['binary'],
                    },
                },
                default: 'data',
                description: 'Name of the outgoing encrypted binary property. Use data for SFTP upload nodes.',
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
                    {
                        name: 'Gzip',
                        value: 'gzip',
                    },
                ],
                default: 'uncompressed',
                description: 'Optional compression applied before encryption for binary input.',
                displayOptions: {
                    show: {
                        inputType: ['binary'],
                    },
                },
            },
        ],
    };

    async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
        const items = this.getInputData();
        const publicKey = await readRecipientPublicKey(this);

        for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
            const item = items[itemIndex];

            try {
                const operation = this.getNodeParameter('operation', itemIndex) as string;
                if (operation !== 'encrypt') {
                    throw new NodeOperationError(this.getNode(), `Unsupported operation: ${operation}`);
                }

                const inputType = this.getNodeParameter('inputType', itemIndex) as string;

                if (inputType === 'text') {
                    const message = this.getNodeParameter('message', itemIndex) as string;
                    item.json = {
                        ...item.json,
                        encrypted: await encryptText(message, publicKey),
                    };
                    continue;
                }

                const binaryPropertyName = this.getNodeParameter('binaryPropertyName', itemIndex) as string;
                const outputBinaryPropertyName = this.getNodeParameter('outputBinaryPropertyName', itemIndex) as string;
                const compressionAlgorithm = this.getNodeParameter('compressionAlgorithm', itemIndex) as string;

                if (!item.binary) {
                    throw new NodeOperationError(this.getNode(), 'Input item has no binary data');
                }

                const sourceBinary = item.binary[binaryPropertyName];
                if (!sourceBinary) {
                    throw new NodeOperationError(this.getNode(), `Binary property "${binaryPropertyName}" does not exist`);
                }

                let binaryData = Buffer.from(sourceBinary.data, 'base64');
                if (compressionAlgorithm !== 'uncompressed') {
                    try {
                        binaryData = DataCompressor.compress(binaryData, compressionAlgorithm);
                    } catch (error) {
                        const message = error instanceof Error ? error.message : String(error);
                        throw new NodeOperationError(this.getNode(), `Binary data could not be compressed: ${message}`);
                    }
                }

                const encryptedMessage = await encryptBinary(binaryData, publicKey);
                const sourceFileName = sourceBinary.fileName || binaryPropertyName;

                item.binary = {
                    ...item.binary,
                    [outputBinaryPropertyName]: {
                        data: Buffer.from(encryptedMessage, 'utf8').toString('base64'),
                        mimeType: 'application/pgp-encrypted',
                        fileName: sourceFileName.endsWith('.pgp') ? sourceFileName : `${sourceFileName}.pgp`,
                    },
                };

                item.json = {
                    ...item.json,
                    encrypted: true,
                    encryptedFileName: item.binary[outputBinaryPropertyName].fileName,
                    encryptedBinaryProperty: outputBinaryPropertyName,
                };
            } catch (error) {
                if (this.continueOnFail()) {
                    items[itemIndex] = {
                        json: {
                            ...item.json,
                            error: error instanceof Error ? error.message : String(error),
                        },
                        pairedItem: itemIndex,
                    };
                    continue;
                }

                if (error instanceof NodeOperationError) {
                    throw error;
                }

                throw new NodeOperationError(this.getNode(), error instanceof Error ? error : new Error(String(error)), {
                    itemIndex,
                });
            }
        }

        return this.prepareOutputData(items);
    }
}
