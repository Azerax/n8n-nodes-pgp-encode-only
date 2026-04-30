import * as openpgp from 'openpgp';
import { Key } from 'openpgp';

export async function encryptText(message: string, publicKey: Key): Promise<string> {
    return (await openpgp.encrypt({
        message: await openpgp.createMessage({ text: message }),
        encryptionKeys: publicKey,
        format: 'armored',
    })) as string;
}

export async function encryptBinary(data: Uint8Array, publicKey: Key): Promise<string> {
    return (await openpgp.encrypt({
        message: await openpgp.createMessage({ binary: data }),
        encryptionKeys: publicKey,
        format: 'armored',
    })) as string;
}
