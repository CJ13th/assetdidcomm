import { Keyring } from '@polkadot/keyring';
import { blake2AsU8a, cryptoWaitReady } from '@polkadot/util-crypto';
import { u8aToHex, stringToU8a } from '@polkadot/util';
import nacl from 'tweetnacl';

/**
 * Create a deterministic x25519 keypair from a wallet signature
 */
function makeEncryptionKeypairFromSignature(signature: Uint8Array) {
    const seed = blake2AsU8a(signature, 256);
    const keyPair = nacl.box.keyPair.fromSecretKey(seed);

    return {
        ...keyPair,
        type: 'x25519',
    };
}

async function main() {
    await cryptoWaitReady();
    // STEP 1: Create a Polkadot-style keyring and add a test account
    const keyring = new Keyring({ type: 'sr25519' });
    const account = keyring.addFromUri('//Alice');

    // STEP 2: Define a fixed message
    const message = 'Create secure key for MyApp';
    const messageBytes = stringToU8a(message);

    // STEP 3: Sign the message
    const signature = account.sign(messageBytes);
    console.log(`Signature: ${u8aToHex(signature)}`);

    // STEP 4: Derive x25519 keypair from signature
    const x25519Keypair = makeEncryptionKeypairFromSignature(signature);

    console.log('\nDerived x25519 Keypair:');
    console.log('Public Key :', u8aToHex(x25519Keypair.publicKey));
    console.log('Secret Key :', u8aToHex(x25519Keypair.secretKey));
    console.log('Type       :', x25519Keypair.type);
}

main().catch(console.error);
