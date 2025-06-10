import { AssetDidCommClient } from '../src/client';
import { CrustStorageAdapter } from '../src/storage/crust';
import { KeyringSigner } from '../src/signers/keyring';
import { MockDidResolver } from '../src/signers/mock';
import { cryptoWaitReady } from '@polkadot/util-crypto'; // <-- 1. Import the initializer

const SENDER_SEED = '//Alice';
const RECIPIENT_DID = 'did:example:receiver';

async function main() {
    await cryptoWaitReady();
    console.log('Crypto WASM initialized.');
    // -------------------

    // Now it is safe to create the signer
    const senderSigner = new KeyringSigner(SENDER_SEED);

    const config = {
        storageAdapter: new CrustStorageAdapter(senderSigner),
        didResolver: new MockDidResolver(),
        signer: senderSigner,
    };

    const client = new AssetDidCommClient(config);

    // The rest of your script remains unchanged...
    const entityId = "testAsset001";
    const bucketId = "mainChatBucket";
    const originalMessageContent = "Hello from KeyringSigner in Node.js! " + Date.now();

    let storageIdForReceipt: string | null = null;

    try {
        console.log("--- Sending Message ---");
        const sendResult = await client.sendDirectMessage(
            entityId,
            bucketId,
            RECIPIENT_DID,
            originalMessageContent
        );
        console.log("Message sent successfully:", sendResult);
        storageIdForReceipt = sendResult.storageIdentifier;

    } catch (error) {
        console.error("Error sending message:", error);
        return;
    }

    if (!storageIdForReceipt) {
        console.error("No storage identifier received, cannot test decryption.");
        return;
    }

    try {
        console.log(`\n--- Receiving Message (from CID: ${storageIdForReceipt}) ---`);
        const decryptedMessage = await client.receiveMessageByCid(
            entityId,
            bucketId,
            storageIdForReceipt
        );

        console.log("\n--- Verification ---");
        console.log("Original Message Content:", originalMessageContent);
        console.log("Decrypted Message Content:", decryptedMessage.body.content);

        if (decryptedMessage.body.content === originalMessageContent) {
            console.log("SUCCESS: Decrypted message content matches original!");
        } else {
            console.error("FAILURE: Decrypted message content does NOT match original.");
        }
    } catch (error) {
        console.error("Error receiving or decrypting message:", error);
    }
}

main().catch(e => console.error("Unhandled error in main:", e));