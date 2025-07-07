import 'dotenv/config';
import { AssetDidCommClient } from '../src/client';
import { PinataStorageAdapter } from '../src/storage/pinata';
import { KeyringSigner } from '../src/signers/keyring';
import { MockDidResolver } from '../src/signers/mock';
import { cryptoWaitReady } from '@polkadot/util-crypto';

// --- Configuration ---
// This test uses a hardcoded development seed. Do not use this in production.
const SENDER_SEED = '//Bob';
const RECIPIENT_DID = 'did:example:charlie';

// Load the Pinata JWT from environment variables for security.
const PINATA_JWT = process.env.PINATA_JWT;
const PINATA_GATEWAY = process.env.PINATA_GATEWAY || 'orange-objective-gerbil-959.mypinata.cloud';
const RPC_ENDPOINT = process.env.RPC_ENDPOINT || 'wss://fraa-flashbox-4654-rpc.a.stagenet.tanssi.network';

async function main() {
    // Check for the required environment variable.
    if (!PINATA_JWT) {
        console.error("FATAL: PINATA_JWT environment variable not set.");
        console.error("Please create a .env file and add your Pinata JWT to it.");
        process.exit(1); // Exit the script if config is missing.
    }

    // Initialize the Polkadot WASM crypto environment.
    await cryptoWaitReady();
    console.log('Crypto WASM initialized.');

    // 1. Create a signer for the sender using a development seed.
    const senderSigner = new KeyringSigner(SENDER_SEED);

    // 2. Configure the AssetDidCommClient with the Pinata adapter.
    const config = {
        storageAdapter: new PinataStorageAdapter({ jwt: PINATA_JWT, publicGateway: `https://${PINATA_GATEWAY}/ipfs` }),
        didResolver: new MockDidResolver(),
        signer: senderSigner,
        rpcEndpoint: RPC_ENDPOINT

    };

    const client = new AssetDidCommClient(config);
    await client.connect();

    // --- Test Logic ---
    const entityId = Math.floor(100000 * Math.random());
    const bucketId = Math.floor(100000 * Math.random());
    const originalMessageContent = "This message was stored on Pinata! " + Date.now();
    let storageIdForReceipt: string | null = null;

    try {
        console.log("\n--- Sending Message via Pinata ---");
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
        return; // Stop if sending failed.
    }

    if (!storageIdForReceipt) {
        console.error("No storage identifier received, cannot test decryption.");
        return;
    }

    try {
        console.log(`\n--- Receiving Message (from CID: ${storageIdForReceipt}) ---`);

        // In a real scenario, a different client/user would perform this step.
        // For this test, we use the same client instance.
        const decryptedMessage = await client.receiveMessageByCid(
            entityId,
            bucketId,
            storageIdForReceipt
        );

        console.log("\n--- Verification ---");
        console.log("Original Message:  ", originalMessageContent);
        console.log("Decrypted Message: ", decryptedMessage.body.content);

        if (decryptedMessage.body.content === originalMessageContent) {
            console.log("\n✅ SUCCESS: Decrypted message content matches the original!");
        } else {
            console.error("\n❌ FAILURE: Decrypted message content does NOT match the original.");
        }
    } catch (error) {
        console.error("Error receiving or decrypting message:", error);
    }
}

// Run the main function and catch any top-level unhandled errors.
main().catch(e => {
    console.error("An unhandled error occurred in the main execution block:", e);
    process.exit(1);
});