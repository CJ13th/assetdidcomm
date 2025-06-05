import { AssetDidCommClient } from '../src/client';
import { MockStorageAdapter, MockDidResolver, MockSigner } from '../src/adapters/mock';

async function main() {
    const config = {
        storageAdapter: new MockStorageAdapter(),
        didResolver: new MockDidResolver(),
        signer: new MockSigner("did:example:test1"), // Sender's DID
        // rpcEndpoint: 'ws://localhost:9944'
    };

    const client = new AssetDidCommClient(config);

    try {
        const result = await client.sendDirectMessage(
            "asset123",       // Entity ID
            "bucketMain",     // Bucket ID
            "did:example:test2", // Recipient DID
            "Hello from AssetDIDComm TypeScript API!"
        );
        console.log("Message sent successfully:", result);
    } catch (error) {
        console.error("Error sending message:", error);
    }
}

main();