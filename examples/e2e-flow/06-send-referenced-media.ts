import { setup, readState, ADMIN_DID } from './_setup';
import * as fs from 'fs';
import * as path from 'path';

async function main() {
    // The Admin/Contributor will send the message
    const { adminClient, disconnectAll } = await setup();
    const state = readState();

    if (state.bucketId === undefined) {
        throw new Error("Bucket ID not found in e2e-state.json. Please run previous scripts first.");
    }

    try {

        // Create the tag required for the media-sharing message ---
        const mediaSharingTag = 'didcomm/media-sharing-v1';

        console.log(`\n--- [ADMIN] 4c. Creating Tag "${mediaSharingTag}" for Bucket ${state.bucketId} ---`);
        // Note: The createTag extrinsic in your spec did not take a namespaceId, just the bucketId.
        const tagTxHash = await adminClient.createTag(state.bucketId, mediaSharingTag);

        console.log(`✅ Tag created successfully. Transaction Hash: ${tagTxHash}`);


        // --- Create a dummy file to send ---
        const dummyContent = `This is a test document for bucket ${state.bucketId}, created at ${new Date().toISOString()}`;
        const dummyFileBytes = new TextEncoder().encode(dummyContent);

        console.log(`\n--- [ADMIN] Sending a referenced media file to Bucket ${state.bucketId} ---`);

        const result = await adminClient.sendMediaMessage(
            state.namespaceId,
            state.bucketId,
            {
                content: dummyFileBytes,
                mediaType: 'text/plain',
                fileName: 'test-document.txt',
                description: 'An important test document.'
            }
        );

        console.log("\n✅ Media message sent successfully!");
        console.log(`   On-Chain Transaction Hash: ${result.messageIdOnChain}`);
        console.log(`   Media File CID (Encrypted): ${result.mediaCid}`);

    } catch (error) {
        console.error("\n❌ Error in Step 6: Send Referenced Media", error);
        process.exit(1);
    } finally {
        await disconnectAll();
    }
}

main().catch(console.error);