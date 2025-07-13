import * as jose from 'jose';
import type { JWK } from 'jose';
import { createKeySharingMessage } from 'message-module-js';
import {
    encryptJWEForMultipleRecipients,
    decryptGeneralJWE,
} from '../src/crypto/encryption';

// This standalone helper function converts a Buffer to Base64URL
function toBase64Url(data: Buffer): string {
    return data.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function main() {
    console.log("--- Running Local JWE Encryption/Decryption Verification Script ---");

    try {
        // --- Step 1: Generate Keys for All Parties ---
        // We will simulate two recipients: the bucket itself and a reader.
        // Both MUST be the same key type (OKP/X25519) to be compatible in a multi-recipient JWE.

        console.log("\n[SETUP] Generating key pair for the Bucket (Recipient 1)...");
        const bucketKeyPair = await jose.generateKeyPair('ECDH-ES+A256KW', { crv: 'X25519', extractable: true });
        const bucketPublicKeyJwk = await jose.exportJWK(bucketKeyPair.publicKey);
        const bucketPrivateKeyJwk = await jose.exportJWK(bucketKeyPair.privateKey);

        console.log("[SETUP] Generating key pair for the Reader (Recipient 2)...");
        const readerKeyPair = await jose.generateKeyPair('ECDH-ES+A256KW', { crv: 'X25519', extractable: true });
        const readerPublicKeyJwk = await jose.exportJWK(readerKeyPair.publicKey);
        const readerPrivateKeyJwk = await jose.exportJWK(readerKeyPair.privateKey);

        console.log("[SETUP] Generating the actual Secret Bucket Key (SKB) that we want to share...");
        const skbKeyPair = await jose.generateKeyPair('ECDH-ES+A256KW', { crv: 'X25519', extractable: true });
        const originalSkbJwk = await jose.exportJWK(skbKeyPair.privateKey);
        originalSkbJwk.use = 'enc'; // Add required property
        originalSkbJwk.kid = 'skb-to-be-shared';

        console.log("\nOriginal SKB to be shared:", originalSkbJwk);

        // --- Step 2: Create the Plaintext DIDComm Message ---
        console.log("\n--- [SENDER] Step 2: Creating DIDComm Key-Sharing Message ---");

        // The WASM binding expects a 'y' coordinate, which X25519 keys don't have.
        // We provide a dummy empty string to satisfy the rigid interface as a workaround.
        const wasmCompatibleSkb = {
            ...originalSkbJwk,
            y: '',
        };

        const keySharingMsgString = createKeySharingMessage({
            id: 'test-message-123',
            from: 'did:example:admin',
            to: ['did:example:bucket', 'did:example:reader'],
            keys: [wasmCompatibleSkb!],
        });
        const plaintextBytes = new TextEncoder().encode(keySharingMsgString);
        console.log("Plaintext message created.");

        // --- Step 3: Encrypt the Message for Multiple Recipients ---
        console.log("\n--- [SENDER] Step 3: Encrypting message for Bucket and Reader ---");
        const recipientsPublicKeys = [bucketPublicKeyJwk, readerPublicKeyJwk];
        const encryptedJwe = await encryptJWEForMultipleRecipients(plaintextBytes, recipientsPublicKeys);
        console.log("Message encrypted successfully!");
        // console.log("Encrypted JWE Object:", JSON.stringify(encryptedJwe, null, 2));


        // --- Step 4: Simulate the Reader Decrypting the Message ---
        console.log("\n--- [READER] Step 4: Decrypting received message with Reader's private key ---");
        const decryptedBytes = await decryptGeneralJWE(encryptedJwe, readerPrivateKeyJwk);
        const decryptedMsgString = new TextDecoder().decode(decryptedBytes);
        const decryptedMsgObject = JSON.parse(decryptedMsgString);
        console.log("Message decrypted successfully!");
        // console.log("Decrypted Message Content:", decryptedMsgObject);


        // --- Step 5: Verify the Contents ---
        console.log("\n--- [VERIFICATION] Step 5: Comparing original SKB with decrypted SKB ---");
        const decryptedSkb = decryptedMsgObject.body.keys[0];

        if (decryptedSkb.d === originalSkbJwk.d) {
            console.log("\n✅✅✅ SUCCESS: The decrypted secret key matches the original secret key!");
        } else {
            console.error("\n❌❌❌ FAILURE: Decrypted key does NOT match the original.");
            console.log("Original 'd':", originalSkbJwk.d);
            console.log("Decrypted 'd':", decryptedSkb.d);
        }

    } catch (error) {
        console.error("\nAn error occurred during the local crypto test:", error);
        process.exit(1);
    }
}

main().catch(console.error);