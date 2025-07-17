import {
    setup,
    writeState,
    writeBackup,
    publishPublicKeyToDid,
    makeEncryptionKeypairFromSignature,
    encryptKeyWithPassword,
    SIGNING_MESSAGE,
    USER_DID,
} from './_setup';
import { u8aToHex, stringToU8a } from '@polkadot/util';

async function main() {
    const { user } = await setup();
    const ONBOARDING_PASSWORD = 'my-strong-password-123';

    console.log("\n--- PHASE 1: First-Time User Onboarding ---");
    console.log("--- PATH A: Create a New Identity ---");

    try {
        // Step 1: Sign the pre-defined message
        console.log(`\n[USER] 1. Signing static message: "${SIGNING_MESSAGE}"`);
        const messageBytes = stringToU8a(SIGNING_MESSAGE);
        const signature = user.sign(messageBytes);
        console.log(`✅ Signature created: ${u8aToHex(signature)}`);

        // Step 2: Derive the Encryption Key Pair from the signature
        console.log("\n[DAPP] 2. Deriving x25519 keypair from signature...");
        const encryptionKeypair = makeEncryptionKeypairFromSignature(signature);
        const publicKeyHex = u8aToHex(encryptionKeypair.publicKey);
        console.log(`✅ Encryption Keypair derived.`);
        console.log(`   - Public Key: ${publicKeyHex}`);

        // Step 3: Publish the public key to the user's DID
        console.log("\n[DAPP] 3. Publishing public key to DID document...");
        publishPublicKeyToDid(USER_DID, publicKeyHex);

        // Step 4: Encrypt the private key with a user-provided password
        console.log(`\n[DAPP] 4. Encrypting private key with password: "${ONBOARDING_PASSWORD}"`);
        const encryptedSecretKey = await encryptKeyWithPassword(encryptionKeypair.secretKey, ONBOARDING_PASSWORD);
        console.log(`✅ Private key encrypted successfully.`);

        // Step 5: Force user to download the backup file
        console.log("\n[DAPP] 5. Creating and saving mandatory backup file...");
        writeBackup({
            did: USER_DID,
            encryptedKey: encryptedSecretKey,
            createdAt: new Date().toISOString()
        });

        // Step 6: Store the encrypted key locally (simulating IndexedDB)
        console.log("\n[DAPP] 6. Storing encrypted key in local state for session use...");
        writeState({
            userDid: USER_DID,
            encryptedKey: encryptedSecretKey,
            sessionPassword: ONBOARDING_PASSWORD, // Storing for test purposes
        });

        console.log("\n\n✅✅✅ Onboarding successfully completed! ✅✅✅");

    } catch (error) {
        console.error("\n❌ Error in Step 1: Create New Identity", error);
        process.exit(1);
    }
}

main().catch(console.error);