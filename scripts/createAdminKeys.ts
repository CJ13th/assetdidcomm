

function u8aToBase64Url(data: Uint8Array): string {
    return Buffer.from(data).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}


import { mnemonicToMiniSecret, cryptoWaitReady } from '@polkadot/util-crypto';
import { Crypto } from '@kiltprotocol/utils';
import { JWK } from 'jose';

async function main() {

    const keyAgreementKey = Crypto.makeEncryptionKeypairFromSeed();

    const publicKeyBase64Url = u8aToBase64Url(keyAgreementKey.publicKey);
    const secretKeyBase64Url = u8aToBase64Url(keyAgreementKey.secretKey);

    const privateKeyJwk: JWK = {
        kty: 'OKP',
        crv: 'X25519',
        x: publicKeyBase64Url,
        d: secretKeyBase64Url,
    };

    console.log(JSON.stringify(privateKeyJwk, null, 2));
}

main();