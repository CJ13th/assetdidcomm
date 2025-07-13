import { setup, readState } from './_setup';
import type { JWK } from 'jose';

// !!! IMPORTANT !!!
// This is the private key corresponding to the `keyAgreement` key on Charlie's DID document.
// In a real application, this key would be securely managed by the user's wallet and
// never exposed directly in code. We define it here ONLY for this E2E test to prove decryption.
// You must generate this key when you create the DID for the Contributor/Charlie account.
const CONTRIBUTOR_PRIVATE_KEY_JWK: JWK = {
    "kty": "OKP",
    "crv": "X25519",
    "x": "ao_-O0e_e2MhOwCiq2KVKzYbLETxQ__zd98UFkwgP0k",
    "d": "DylBSNITA4q0kE3G_gPToCZ9N9kXRVMNbnQlxCdpNkM"
};


async function main() {
    const { contributorClient, disconnectAll } = await setup();
    const state = readState();

    if (state.bucketId === undefined || !state.bucketSkJwk) {
        throw new Error("Bucket ID or original SKB not found in e2e-state.json. Please run previous scripts first.");
    }

    try {
        // --- Step 8: Retrieve and Decrypt SKB ---
        console.log(`\n--- [READER] 5. Retrieving and Decrypting SKB for Bucket ${state.bucketId} ---`);
        const retrievedSkb = await contributorClient.retrieveBucketSecretKey(state.bucketId, CONTRIBUTOR_PRIVATE_KEY_JWK);

        console.log("\n--- VERIFICATION ---");
        console.log("Original SKB:", state.bucketSkJwk);
        console.log("Retrieved SKB:", retrievedSkb);

        // A simple verification by comparing a property of the secret keys
        if (retrievedSkb.d === state.bucketSkJwk.d) {
            console.log("\n✅ SUCCESS: Contributor successfully retrieved the correct bucket secret key!");
        } else {
            console.error("\n❌ FAILURE: Retrieved SKB does not match the original.");
            process.exit(1);
        }

    } catch (error) {
        console.error("\n❌ Error in Step 5: Reader Retrieves SKB", error);
        process.exit(1);
    } finally {
        await disconnectAll();
    }
}

main().catch(console.error);