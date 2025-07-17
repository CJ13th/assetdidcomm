
import * as jose from 'jose';
async function generateKeys() {
    const { publicKey, privateKey } = await jose.generateKeyPair('ECDH-ES+A256KW', { extractable: true });
    console.log('Public JWK:', await jose.exportJWK(publicKey));
    console.log('Private JWK:', await jose.exportJWK(privateKey));
}


import { blake2AsU8a } from '@polkadot/util-crypto';
import nacl from 'tweetnacl';

/**
 * Generates a deterministic x25519 keypair from a wallet signature.
 *
 * @param signature The signature returned from signing a static message.
 * @returns x25519-compatible keypair
 */
export function makeEncryptionKeypairFromSignature(signature: Uint8Array) {
    // Derive a 32-byte seed from the signature using blake2b (or sha256)
    const seed = blake2AsU8a(signature, 256);

    // Generate x25519 keypair from the seed
    const keyPair = nacl.box.keyPair.fromSecretKey(seed);

    return {
        ...keyPair,
        type: 'x25519',
    };
}


generateKeys();