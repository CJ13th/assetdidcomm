
import * as jose from 'jose';
async function generateKeys() {
    const { publicKey, privateKey } = await jose.generateKeyPair('ECDH-ES+A256KW', { extractable: true });
    console.log('Public JWK:', await jose.exportJWK(publicKey));
    console.log('Private JWK:', await jose.exportJWK(privateKey));
}
generateKeys();