import {
    setup,
    readBackup,
    writeState,
    fetchPublicKeyFromDid,
    decryptKeyWithPassword,
    encryptKeyWithPassword,
} from './_setup';
import nacl from 'tweetnacl';
import { u8aToHex } from '@polkadot/util';

async function main() {
    const { user } = await setup();
    const BACKUP_PASSWORD = 'my-strong-password-123'; // The password used in the first script
    const NEW_SESSION_PASSWORD = 'new-device-password-456';

    console.log("\n--- PHASE 1: User Onboarding on a New Device ---");
    console.log("--- PATH B: Import From Backup File ---");

    try {
        // Step 1: User provides their backup file
        console.log("\n[DAPP] 1. Reading the user's backup file...");
        const backupData = readBackup();
        console.log(`✅ Backup file loaded for DID: ${backupData.did}`);

        // Step 2: User provides the password for the backup
        console.log(`\n[DAPP] 2. Decrypting private key with backup password: "${BACKUP_PASSWORD}"`);
        const decryptedSecretKey = await decryptKeyWithPassword(backupData.encryptedKey, BACKUP_PASSWORD);
        console.log(`✅ Private key decrypted successfully.`);

        // Step 3: Verify ownership by checking against the DID public key
        console.log("\n[DAPP] 3. Verifying key ownership against DID document...");
        const { publicKey } = nacl.box.keyPair.fromSecretKey(decryptedSecretKey);
        const derivedPublicKeyHex = u8aToHex(publicKey);

        const didPublicKeyHex = fetchPublicKeyFromDid(backupData.did);

        if (derivedPublicKeyHex !== didPublicKeyHex) {
            throw new Error("Verification Failed: Imported key does not match public key on DID.");
        }
        console.log("✅ Ownership verified! Derived public key matches the one on the DID.");

        // Step 4: User creates a new session password for this new device
        console.log(`\n[DAPP] 4. Re-encrypting private key with new session password: "${NEW_SESSION_PASSWORD}"`);
        const newEncryptedSecretKey = await encryptKeyWithPassword(decryptedSecretKey, NEW_SESSION_PASSWORD);
        console.log("✅ Private key re-encrypted for new session.");

        // Step 5: Store the newly encrypted key locally for this new device
        console.log("\n[DAPP] 5. Storing new encrypted key in local state...");
        writeState({
            userDid: backupData.did,
            encryptedKey: newEncryptedSecretKey,
            sessionPassword: NEW_SESSION_PASSWORD, // Storing for test purposes
        });

        console.log("\n\n✅✅✅ Import and setup on new device successful! ✅✅✅");

    } catch (error) {
        console.error("\n❌ Error in Step 2: Import From Backup", error);
        process.exit(1);
    }
}

main().catch(console.error);