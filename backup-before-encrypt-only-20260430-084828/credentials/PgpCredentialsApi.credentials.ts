import { IAuthenticateGeneric, ICredentialType, INodeProperties } from 'n8n-workflow';

export class PgpCredentialsApi implements ICredentialType {
    name = 'pgpCredentialsApi';
    displayName = 'PGP Encrypt Only API';
    // @ts-ignore
    icon = 'file:key.svg';
    documentationUrl = 'https://openpgpjs.org/';
    properties: INodeProperties[] = [
        {
            displayName: 'Key Method',
            name: 'keyMethod',
            type: 'options',
            options: [
                {
                    name: 'Manual',
                    value: 'manual',
                },
                {
                    name: 'Server',
                    value: 'server',
                },
            ],
            default: 'manual',
            description: 'Choose whether to paste the recipient public key or fetch it from a URL.',
        },
        {
            displayName: 'Public Key',
            name: 'public_key',
            type: 'string',
            description: 'Recipient ASCII-armored PGP public key used for encryption only.',
            hint: 'Paste the full public key block including BEGIN and END lines.',
            typeOptions: {
                rows: 12,
                password: true,
            },
            default: '',
            required: false,
            displayOptions: {
                show: {
                    keyMethod: ['manual'],
                },
            },
        },
        {
            displayName: 'Public Key URL',
            name: 'publicKeyFile',
            type: 'string',
            default: '',
            description: 'URL where the recipient public key is stored.',
            hint: 'The response body must be the ASCII-armored PGP public key.',
            typeOptions: {
                password: true,
            },
            displayOptions: {
                show: {
                    keyMethod: ['server'],
                },
            },
        },
    ];

    authenticate: IAuthenticateGeneric = {
        type: 'generic',
        properties: {},
    };
}
