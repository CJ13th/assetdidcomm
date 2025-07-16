import * as jose from 'jose';
import { setup, readState, writeState, writeKeyState, CONTRIBUTOR_DID_URI, ADMIN_PRIVATE_KEY_JWK } from './_setup';

async function main() {
    const { adminClient, disconnectAll } = await setup();
    const state = readState();

    if (!state.namespaceId || state.bucketId === undefined) {
        throw new Error("Namespace/Bucket ID not found in e2e-state.json. Please run previous scripts first.");
    }

    try {
        // --- Step 5: Generate Bucket Keys (off-chain) ---
        console.log(`\n--- [ADMIN] 4a. Generating Bucket Keys ---`);
        const { publicKey, privateKey } = await jose.generateKeyPair('ECDH-ES+A256KW', { crv: 'X25519', extractable: true });
        const bucketPkJwk = await jose.exportJWK(publicKey);
        const bucketSkJwk = await jose.exportJWK(privateKey);


        // This is required by the validation check in the shareBucketKey function.
        bucketPkJwk.use = 'enc';
        bucketSkJwk.use = 'enc';

        const numericKeyId = Math.floor(Math.random() * 1_000_000_000_000);

        bucketSkJwk.kid = numericKeyId.toString();
        bucketPkJwk.kid = numericKeyId.toString();
        // -------------------------------------------------------------

        // Generate a simple numeric ID that fits in a u128.

        // Add a key ID (kid) to the public key for on-chain identification
        console.log(`🔑 Bucket Public Key (PKB) generated. On-chain ID will be: ${numericKeyId}`);

        // --- Step 6: Set Public Key ID on-chain ---
        console.log(`\n--- [ADMIN] 4b. Setting Bucket Public Key ID on-chain ---`);
        const setKeyTxHash = await adminClient.setBucketPublicKey(state.namespaceId, state.bucketId, numericKeyId);
        console.log(`✅ Bucket public key ID set successfully. Transaction Hash: ${setKeyTxHash}`);

        // Create the tag required for the key-sharing message ---
        const keySharingTag = 'didcomm/key-sharing-v1';
        console.log(`\n--- [ADMIN] 4c. Creating Tag "${keySharingTag}" for Bucket ${state.bucketId} ---`);
        // Note: The createTag extrinsic in your spec did not take a namespaceId, just the bucketId.
        const tagTxHash = await adminClient.createTag(state.bucketId, keySharingTag);
        console.log(`✅ Tag created successfully. Transaction Hash: ${tagTxHash}`);
        // --- Step 7: Share Secret Key with Contributor/Reader ---
        console.log(`\n--- [ADMIN] 4c. Sharing Secret Key with Reader (did:kilt:4p8Azs17Bod3LMHHoVWK3KHzbmKicnPpF28b96c6HYApfFu8) ---`);

        // Store the key in our off-chain key file BEFORE trying to share it,
        // so the `shareBucketKey` function can resolve it via `fetchBucketPublicKey`.
        writeKeyState({ [numericKeyId]: bucketPkJwk });

        await adminClient.shareBucketKey(
            state.namespaceId,
            state.bucketId,
            { publicJwk: bucketPkJwk, secretJwk: bucketSkJwk },
            [CONTRIBUTOR_DID_URI],
            ADMIN_PRIVATE_KEY_JWK
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