import { setup, writeState } from './_setup';

async function main() {
    const { managerClient, disconnectAll } = await setup();

    try {
        // --- Step 1: Create a new Namespace ---
        // A unique ID for the entity/namespace
        const namespaceId = Math.floor(Math.random() * 1_000_000_000);

        console.log(`\n--- [MANAGER] 1. Creating Namespace: ${namespaceId} ---`);
        const txHash = await managerClient.createEntity(namespaceId, { name: "E2E Test Asset" });
        console.log(`✅ Namespace created successfully! Transaction Hash: ${txHash}`);

        // Write the new namespaceId to our shared state file for the next script to use
        writeState({ namespaceId });

    } catch (error) {
        console.error("\n❌ Error in Step 1: Create Namespace", error);
        process.exit(1);
    } finally {
        await disconnectAll();
    }
}

main().catch(console.error);