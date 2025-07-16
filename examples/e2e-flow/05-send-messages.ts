import { setup, readState, CONTRIBUTOR_PRIVATE_KEY_JWK } from './_setup';

async function main() {
    // We need clients for the Manager (Alice), Admin (Bob), and Contributor (Charlie)
    const { managerClient, adminClient, contributorClient, disconnectAll } = await setup();
    const state = readState();

    if (!state.namespaceId || state.bucketId === undefined) {
        throw new Error("State not found. Please run scripts 01-04 first.");
    }

    // For this test, Charlie will be the one fetching the feed at the end.
    const readerClient = contributorClient;

    try {

        // --- STEP 1: Alice (Manager) sends a welcome message ---
        console.log("\n--- [ALICE] Sending first message ---");
        await managerClient.sendDirectMessage(
            state.namespaceId,
            state.bucketId,
            `bucket:${state.bucketId}`, // Target the bucket itself
            "Welcome to the project bucket everyone!"
        );
        console.log("Alice's message sent.");


        // --- STEP 2: Bob (Admin) sends a status update ---
        console.log("\n--- [BOB] Sending second message ---");
        await adminClient.sendDirectMessage(
            state.namespaceId,
            state.bucketId,
            `bucket:${state.bucketId}`,
            "I have set up the initial permissions. Please start uploading your documents."
        );
        console.log("Bob's message sent.");

        const mediaSharingTag = 'didcomm/media-sharing-v1';
        console.log(`\n--- [ADMIN] Creating Tag "${mediaSharingTag}" for Bucket ${state.bucketId} ---`);
        const mediaTagTxHash = await adminClient.createTag(state.bucketId, mediaSharingTag);
        console.log(`✅ Tag created successfully. Transaction Hash: ${mediaTagTxHash}`);



        // --- STEP 3: Charlie (Contributor) sends a media file ---
        console.log("\n--- [CHARLIE] Sending a media message ---");
        const reportContent = `This is the second weekly report. All systems are broken!`;
        const reportBytes = new TextEncoder().encode(reportContent);
        await contributorClient.sendMediaMessage(
            state.namespaceId,
            state.bucketId,
            {
                content: reportBytes,
                mediaType: 'text/plain',
                fileName: 'weekly-report-2.txt',
            }
        );
        console.log("Charlie's media message sent.");

    } catch (error) {
        console.error("\n❌ Error in sending messages:", error);
        process.exit(1);
    } finally {
        await disconnectAll();
    }
}

main().catch(console.error);