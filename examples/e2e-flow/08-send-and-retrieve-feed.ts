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

        // // --- STEP 1: Alice (Manager) sends a welcome message ---
        // console.log("\n--- [ALICE] Sending first message ---");
        // await managerClient.sendDirectMessage(
        //     state.namespaceId,
        //     state.bucketId,
        //     `bucket:${state.bucketId}`, // Target the bucket itself
        //     "Welcome to the project bucket everyone!"
        // );
        // console.log("Alice's message sent.");


        // // --- STEP 2: Bob (Admin) sends a status update ---
        // console.log("\n--- [BOB] Sending second message ---");
        // await adminClient.sendDirectMessage(
        //     state.namespaceId,
        //     state.bucketId,
        //     `bucket:${state.bucketId}`,
        //     "I have set up the initial permissions. Please start uploading your documents."
        // );
        // console.log("Bob's message sent.");


        // // --- STEP 3: Charlie (Contributor) sends a media file ---
        // console.log("\n--- [CHARLIE] Sending a media message ---");
        // const reportContent = `This is the first weekly report. All systems are nominal.`;
        // const reportBytes = new TextEncoder().encode(reportContent);
        // await contributorClient.sendMediaMessage(
        //     state.namespaceId,
        //     state.bucketId,
        //     {
        //         content: reportBytes,
        //         mediaType: 'text/plain',
        //         fileName: 'weekly-report-1.txt',
        //     }
        // );
        // console.log("Charlie's media message sent.");


        // --- FINAL STEP: Charlie retrieves and displays the entire feed ---
        const messageFeed = await readerClient.retrieveBucketMessages(state.bucketId, CONTRIBUTOR_PRIVATE_KEY_JWK);

        console.log("\n\n" + "=".repeat(80));
        console.log(`✅✅✅ BUCKET FEED SUCCESSFULLY RETRIEVED (${messageFeed.length} messages) ✅✅✅`);
        console.log("=".repeat(80));

        for (const msg of messageFeed) {
            console.log(`\n[Message #${msg.messageId}]-----------------------------------------`);
            console.log(`  On-Chain Submitter: ${msg.onChainSubmitter}`);
            console.log(`  DIDComm Sender:       ${msg.from}`);
            console.log(`  Message Type:         ${msg.type}`);

            // Display content based on message type
            if (msg.type.includes('basicmessage')) {
                console.log(`  Content:              "${msg.body.content}"`);
            } else if (msg.type.includes('media-sharing')) {
                console.log(`  Attachments:`);
                for (const item of msg.body.items) {
                    console.log(`    - ID: ${item.attachment_id}, Link: ${item.link || 'Inlined'}`);
                }
            }
        }
        console.log("\n" + "=".repeat(80));


    } catch (error) {
        console.error("\n❌ Error in Step 8: Send and Retrieve Feed", error);
        process.exit(1);
    } finally {
        await disconnectAll();
    }
}

main().catch(console.error);