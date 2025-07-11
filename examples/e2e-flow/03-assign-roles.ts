import { setup, readState, ADMIN_DID, CONTRIBUTOR_DID } from './_setup';

async function main() {
    // We need both manager and admin clients for this step
    const { managerClient, adminClient, disconnectAll } = await setup();
    const state = readState();

    if (!state.namespaceId || state.bucketId === undefined) {
        throw new Error("Namespace/Bucket ID not found in e2e-state.json. Please run previous scripts first.");
    }

    try {
        // --- Step 3: Assign Admin by Manager ---
        console.log(`\n--- [MANAGER] 3a. Assigning Admin (${ADMIN_DID}) to Bucket ${state.bucketId} ---`);
        const adminTxHash = await managerClient.addAdmin(state.namespaceId, state.bucketId, ADMIN_DID);
        console.log(`✅ Admin assigned successfully. Transaction Hash: ${adminTxHash}`);

        // --- Step 4: Assign Contributor by Admin ---
        console.log(`\n--- [ADMIN] 3b. Assigning Contributor (${CONTRIBUTOR_DID}) to Bucket ${state.bucketId} ---`);
        const contributorTxHash = await adminClient.addContributor(state.namespaceId, state.bucketId, CONTRIBUTOR_DID);
        console.log(`✅ Contributor assigned successfully. Transaction Hash: ${contributorTxHash}`);

    } catch (error) {
        console.error("\n❌ Error in Step 3: Assign Roles", error);
        process.exit(1);
    } finally {
        await disconnectAll();
    }
}

main().catch(console.error);