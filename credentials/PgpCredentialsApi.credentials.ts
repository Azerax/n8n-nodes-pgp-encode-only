import { IAuthenticateGeneric, ICredentialType, INodeProperties } from 'n8n-workflow';

export class PgpCredentialsApi implements ICredentialType {
    name = 'pgpCredentialsApi';
    displayName = 'PGP API';
    // @ts-ignore
    icon = 'file:key.svg';
    documentationUrl = 'https://openpgpjs.org/';
    properties: INodeProperties[] = [
        {
            displayName: 'Passphrase',
            name: 'passphrase',
            type: 'string',
            typeOptions: {
                password: true,
            },
            default: '',
            required: false,
        },
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
						}
					],
					default: 'manual',
				},
        {
            displayName: 'Encryption Key',
            name: 'public_key',
            type: 'string',
						description: 'A plain text version of a key',
						hint: 'The key to use to encrypt the message. Typically the recipient\'s Public Key',
            typeOptions: {
                rows: 5,
								password: true,
            },
            default: '',
            required: false,
						displayOptions:	{
							show: {
								keyMethod: [
									'manual'
								]
							},
						}
        },
				{
					displayName: 'Encryption Key',
					name: 'publicKeyFile',
					type: 'string',
					default: '',
					description: 'The url where the key is stored',
					hint: 'The key to use to encrypt the message. Typically the recipient\'s Public Key',
					typeOptions: {
						password: true,
					},
					displayOptions: {
						show: {
								keyMethod: [
									'server'
								]
							},
					},
				},
        {
            displayName: 'Decryption Key',
            name: 'private_key',
            type: 'string',
						description: 'A plain text version of a key',
						hint: 'The key to use to decrypt the message. Typically the sender\'s Private Key',
            typeOptions: {
                rows: 5,
								password: true,
            },
            default: '',
            required: false,
						displayOptions:	{
							show: {
								keyMethod: [
									'manual'
								]
							},
						},
        },
				{
					displayName: 'Decryption Key',
					name: 'privateURL',
					type: 'string',
					default: '',
					description: 'The url where the key is stored',
					hint: 'The key to use to decrypt the message. Typically the sender\'s Private Key',
					typeOptions: {
								password: true,
            },
					displayOptions: {
						show: {
								keyMethod: [
									'server'
								]
							},
					},
				},
    ];

    authenticate: IAuthenticateGeneric = {
        type: 'generic',
        properties: {},
    };
}
