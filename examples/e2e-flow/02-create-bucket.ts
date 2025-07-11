import { setup, readState, writeState } from './_setup';

async function main() {
    const { managerClient, disconnectAll } = await setup();
    const state = readState();

    if (!state.namespaceId) {
        throw new Error("Namespace ID not found in e2e-state.json. Please run 01-create-namespace.ts first.");
    }

    try {
        // --- Step 2: Create a Bucket in the Namespace ---
        console.log(`\n--- [MANAGER] 2. Creating Bucket in Namespace: ${state.namespaceId} ---`);
        const { bucketId, txHash } = await managerClient.createBucket(state.namespaceId, { purpose: "Document Storage" });
        console.log(`✅ Bucket created successfully with ID: ${bucketId}. Transaction Hash: ${txHash}`);

        // Write the new bucketId to our state file
        writeState({ bucketId });

    } catch (error) {
        console.error("\n❌ Error in Step 2: Create Bucket", error);
        process.exit(1);
    } finally {
        await disconnectAll();
    }
}

main().catch(console.error);