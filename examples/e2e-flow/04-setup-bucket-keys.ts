import * as jose from 'jose';
import { setup, readState, writeState, writeKeyState, CONTRIBUTOR_DID } from './_setup';

async function main() {
    const { adminClient, disconnectAll } = await setup();
    const state = readState();

    if (!state.namespaceId || state.bucketId === undefined) {
        throw new Error("Namespace/Bucket ID not found in e2e-state.json. Please run previous scripts first.");
    }

    try {
        // --- Step 5: Generate Bucket Keys (off-chain) ---
        console.log(`\n--- [ADMIN] 4a. Generating Bucket Keys ---`);
        const { publicKey, privateKey } = await jose.generateKeyPair('ECDH-ES+A256KW', { extractable: true });
        const bucketPkJwk = await jose.exportJWK(publicKey);
        const bucketSkJwk = await jose.exportJWK(privateKey);


        // This is required by the validation check in the shareBucketKey function.
        bucketPkJwk.use = 'enc';
        bucketSkJwk.use = 'enc';
        // -------------------------------------------------------------

        // Generate a simple numeric ID that fits in a u128.
        const numericKeyId = Math.floor(Math.random() * 1_000_000_000_000);

        // Add a key ID (kid) to the public key for on-chain identification
        bucketPkJwk.kid = `numeric-id-${numericKeyId}`;
        console.log(`🔑 Bucket Public Key (PKB) generated. On-chain ID will be: ${numericKeyId}`);

        // --- Step 6: Set Public Key ID on-chain ---
        console.log(`\n--- [ADMIN] 4b. Setting Bucket Public Key ID on-chain ---`);
        const setKeyTxHash = await adminClient.setBucketPublicKey(state.namespaceId, state.bucketId, numericKeyId);
        console.log(`✅ Bucket public key ID set successfully. Transaction Hash: ${setKeyTxHash}`);

        // --- Step 7: Share Secret Key with Contributor/Reader ---
        console.log(`\n--- [ADMIN] 4c. Sharing Secret Key with Reader (${CONTRIBUTOR_DID}) ---`);

        // Store the key in our off-chain key file BEFORE trying to share it,
        // so the `shareBucketKey` function can resolve it via `fetchBucketPublicKey`.
        writeKeyState({ [numericKeyId]: bucketPkJwk });

        await adminClient.shareBucketKey(
            state.namespaceId,
            state.bucketId,
            { publicJwk: bucketPkJwk, secretJwk: bucketSkJwk },
            [CONTRIBUTOR_DID]
        );
        console.log(`✅ Bucket secret key shared successfully.`);

        // Save the full keys to the main state file for the verification step.
        writeState({ bucketPkJwk, bucketSkJwk });

    } catch (error) {
        console.error("\n❌ Error in Step 4: Setup Bucket Keys", error);
        process.exit(1);
    } finally {
        await disconnectAll();
    }
}

main().catch(console.error);