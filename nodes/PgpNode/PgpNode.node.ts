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

    key = key
        .replace(/\\r\\n/g, '\n')
        .replace(/\\n/g, '\n')
        .replace(/\r\n/g, '\n')
        .replace(/\r/g, '\n');

    if ((key.startsWith('"') && key.endsWith('"')) || (key.startsWith("'") && key.endsWith("'"))) {
        key = key.slice(1, -1).trim();
    }

    const begin = key.indexOf('-----BEGIN PGP PUBLIC KEY BLOCK-----');
    const endMarker = '-----END PGP PUBLIC KEY BLOCK-----';
    const end = key.indexOf(endMarker);
    if (begin >= 0 && end >= begin) {
        key = key.slice(begin, end + endMarker.length).trim();
    }

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

    try {
        return await openpgp.readKey({ armoredKey: normalizedKey });
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new NodeOperationError(context.getNode(), `Public key could not be parsed: ${message}`);
    }
}

export class PgpNode implements INodeType {
    description: INodeTypeDescription = {
        displayName: 'PGP Encrypt Only',
        name: 'pgpNode',
        icon: 'file:key.svg',
        group: ['transform'],
        version: 1,
        description: 'Encrypt text or binary data with a public key only.',
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
                default: 'encrypt',
                options: [{ name: 'Encrypt', value: 'encrypt' }],
            },
            {
                displayName: 'Input Type',
                name: 'inputType',
                type: 'options',
                options: [
                    { name: 'Text', value: 'text' },
                    { name: 'Binary', value: 'binary' },
                ],
                default: 'binary',
            },
            {
                displayName: 'Message',
                name: 'message',
                type: 'string',
                default: '',
                displayOptions: {
                    show: { inputType: ['text'] },
                },
            },
            {
                displayName: 'Binary Property Name',
                name: 'binaryPropertyName',
                type: 'string',
                default: 'data',
                displayOptions: {
                    show: { inputType: ['binary'] },
                },
            },
            {
                displayName: 'Output Binary Property Name',
                name: 'outputBinaryPropertyName',
                type: 'string',
                default: 'data',
                displayOptions: {
                    show: { inputType: ['binary'] },
                },
            },
            {
                displayName: 'Compression Algorithm',
                name: 'compressionAlgorithm',
                type: 'options',
                options: [
                    { name: 'Uncompressed', value: 'uncompressed' },
                    { name: 'Zip', value: 'zip' },
                    { name: 'Zlib', value: 'zlib' },
                    { name: 'Gzip', value: 'gzip' },
                ],
                default: 'uncompressed',
                displayOptions: {
                    show: { inputType: ['binary'] },
                },
            },
        ],
    };

    async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
        const items = this.getInputData();
        const publicKey = await readRecipientPublicKey(this);

        for (let i = 0; i < items.length; i++) {
            const item = items[i];

            try {
                const inputType = this.getNodeParameter('inputType', i) as string;

                if (inputType === 'text') {
                    const message = this.getNodeParameter('message', i) as string;
                    item.json = {
                        ...item.json,
                        encrypted: await encryptText(message, publicKey),
                    };
                    continue;
                }

                const binaryPropertyName = this.getNodeParameter('binaryPropertyName', i) as string;
                const outputBinaryPropertyName = this.getNodeParameter('outputBinaryPropertyName', i) as string;
                const compressionAlgorithm = this.getNodeParameter('compressionAlgorithm', i) as string;

                if (!item.binary?.[binaryPropertyName]) {
                    throw new NodeOperationError(this.getNode(), 'Missing binary input');
                }

                // 🔥 FIXED TYPE ISSUE HERE
                let binaryData: Uint8Array = Buffer.from(item.binary[binaryPropertyName].data, 'base64');

                if (compressionAlgorithm !== 'uncompressed') {
                    binaryData = DataCompressor.compress(binaryData, compressionAlgorithm);
                }

                const encrypted = await encryptBinary(binaryData, publicKey);

                item.binary = {
                    ...item.binary,
                    [outputBinaryPropertyName]: {
                        data: Buffer.from(encrypted).toString('base64'),
                        mimeType: 'application/pgp-encrypted',
                        fileName: `${item.binary[binaryPropertyName].fileName || 'file'}.pgp`,
                    },
                };

                item.json = {
                    ...item.json,
                    encrypted: true,
                };

            } catch (error) {
                throw new NodeOperationError(this.getNode(), error as Error);
            }
        }

        return this.prepareOutputData(items);
    }
}