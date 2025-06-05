// examples/sendAndReceiveMessage.ts
import { AssetDidCommClient } from '../src/client';
import { MockStorageAdapter, MockDidResolver, MockSigner } from '../src/adapters/mock';

async function main() {
    const config = {
        storageAdapter: new MockStorageAdapter(),
        didResolver: new MockDidResolver(),
        signer: new MockSigner("did:example:sender"), // Sender's DID
    };

    const client = new AssetDidCommClient(config);

    const entityId = "testAsset001";
    const bucketId = "mainChatBucket";
    const recipientDid = "did:example:receiver";
    const originalMessageContent = "Hello, this is a test message for send and receive! " + Date.now();

    let storageIdForReceipt: string | null = null;

    try {
        console.log("--- Sending Message ---");
        const sendResult = await client.sendDirectMessage(
            entityId,
            bucketId,
            recipientDid,
            originalMessageContent
        );
        console.log("Message sent successfully:", sendResult);
        storageIdForReceipt = sendResult.storageIdentifier; // Get the CID for decryption

        // Basic check of the JWE structure (optional)
        if (sendResult.jwe.split('.').length !== 5) {
            console.error("Generated JWE does not look like a compact JWE!");
        }

    } catch (error) {
        console.error("Error sending message:", error);
        return; // Stop if sending failed
    }

    if (!storageIdForReceipt) {
        console.error("No storage identifier received, cannot test decryption.");
        return;
    }

    try {
        console.log(`\n--- Receiving Message (from CID: ${storageIdForReceipt}) ---`);
        // Simulate a different client instance or context that would be "receiving"
        // For this test, we use the same client instance but it will use the MOCK_SKB_JWK
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
        // You can add more assertions here (e.g., check 'from', 'to', 'id' fields)
        // console.log("Original 'from':", client.config.signer.getAddress());
        // console.log("Decrypted 'from':", decryptedMessage.from);

    } catch (error) {
        console.error("Error receiving or decrypting message:", error);
    }
}

main().catch(e => console.error("Unhandled error in main:", e));