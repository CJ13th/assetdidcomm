import { readState, decryptKeyWithPassword, writeState } from './_setup';
import { u8aToHex } from '@polkadot/util';

async function main() {
    console.log("\n--- PHASE 2: Returning User Session Unlock ---");
    const state = readState();

    if (!state.encryptedKey || !state.sessionPassword) {
        throw new Error("User state not found. Please run 01 or 02 scripts first.");
    }

    try {
        // Step 1: dApp finds the stored encrypted key
        console.log("\n[DAPP] 1. Found encrypted key in local storage.");

        // Step 2: dApp prompts user for their session password
        console.log(`\n[DAPP] 2. Prompting for session password... (Using: "${state.sessionPassword}")`);

        // Step 3: Decrypt the key and load into memory
        const unlockedSecretKey = await decryptKeyWithPassword(state.encryptedKey, state.sessionPassword);
        const unlockedSecretKeyHex = u8aToHex(unlockedSecretKey);

        console.log("\n[DAPP] 3. Decrypting key and loading into memory...");
        console.log(`✅ Success! Private key decrypted.`);
        // In a real app, this is held in a variable. We'll log it for verification.
        console.log(`   - Unlocked Private Key (in memory): ${unlockedSecretKeyHex.substring(0, 32)}...`);

        // Save the unlocked key to state so other scripts could hypothetically use it
        writeState({ unlockedSecretKeyHex });

        console.log("\n\n✅✅✅ Session Unlocked. dApp is now fully functional. ✅✅✅");

    } catch (error) {
        console.error("\n❌ Error in Step 3: Session Unlock", error);
        process.exit(1);
    }
}

main().catch(console.error);