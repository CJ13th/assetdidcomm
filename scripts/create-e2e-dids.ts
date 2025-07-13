import 'dotenv/config';
import * as Kilt from '@kiltprotocol/sdk-js';
import type { DidDocument, KiltKeyringPair } from '@kiltprotocol/types';
import { Crypto } from '@kiltprotocol/utils';
import type { JWK } from 'jose';
import * as fs from 'fs';

/**
 * Creates a DID with a key agreement key for a specific user, using their seed.
 * This function follows the structure of your original script.
 */
async function createDidForUser(
    api: Kilt.KiltApi,
    submitterAccount: KiltKeyringPair,
    userName: string,
    userSeed: string,
): Promise<any> {
    console.log(`\n-------------------\n🚀 Starting DID Creation for: ${userName}\n-------------------`);

    // 1. Generate keypairs for the new DID.
    // The authentication key is derived from the user's seed (//Alice, etc.)
    // This ensures the DID is controlled by their well-known AccountId.
    const authenticationKey = Crypto.makeKeypairFromUri(userSeed, 'sr25519');
    console.log(`🔑 ${userName}'s Authentication AccountId: ${authenticationKey.address}`);

    // A key agreement (encryption) key is generated randomly for each user.
    const keyAgreementKey = Crypto.makeEncryptionKeypairFromSeed();
    console.log(`🔑 Generated new Key Agreement (Encryption) Key for ${userName}.`);

    // 2. Create the DID on the blockchain with the authentication key.
    console.log(`\n⛓️  Submitting createDid transaction for ${userName}...`);
    const createDidResult = await Kilt.DidHelpers.createDid({
        api,
        submitter: submitterAccount,
        signers: [authenticationKey],
        fromPublicKey: authenticationKey,
    }).submit({ awaitFinalized: false }); // Using the submission pattern from your script

    if (createDidResult.status !== 'confirmed') {
        throw new Error(`Failed to create DID for ${userName}. Status: ${createDidResult.status}`);
    }
    let didDocument = createDidResult.asConfirmed.didDocument;
    console.log(`✅ DID ${didDocument.id} created successfully.`);

    // 3. Add the key agreement key to the newly created DID.
    console.log(`\n⛓️  Submitting setVerificationMethod transaction for ${userName} to add encryption key...`);
    const addKeyResult = await Kilt.DidHelpers.setVerificationMethod({
        api,
        didDocument,
        submitter: submitterAccount,
        signers: [authenticationKey], // The DID's auth key must sign this update
        publicKey: keyAgreementKey,
        relationship: 'keyAgreement',
    }).submit({ awaitFinalized: false });

    if (addKeyResult.status !== 'confirmed') {
        throw new Error(`Failed to add key agreement key for ${userName}. Status: ${addKeyResult.status}`);
    }
    console.log('✅ Key Agreement key added successfully.');

    // 4. Manually construct the private key JWK needed for E2E testing.
    const keyAgreementSecretKeyJwk: JWK = {
        kty: 'OKP',
        crv: 'X25519',
        use: 'enc',
        x: Buffer.from(keyAgreementKey.publicKey).toString('base64url'),
        d: Buffer.from(keyAgreementKey.secretKey).toString('base64url'),
    };

    return {
        userName,
        accountId: authenticationKey.address,
        didUri: didDocument.id,
        keyAgreementSecretKeyJwk,
    };
}


async function main() {
    // Setup connection using the pattern from your script
    const api = await Kilt.connect('wss://peregrine.kilt.io');
    await Kilt.init();
    console.log('✅ Successfully connected to the KILT blockchain.');

    // 1. Set up a funded account from .env to pay for transactions.
    if (!process.env.KILT_FAUCET_SEED) {
        throw new Error("KILT_FAUCET_SEED not found in .env file. This account is required to pay for transactions.");
    }
    const submitter = Crypto.makeKeypairFromUri(process.env.KILT_FAUCET_SEED);
    console.log(`🔑 Using Submitter Account: ${submitter.address} to pay for all transactions.`);

    // 2. Define the users to create DIDs for.
    const usersToCreate = [
        { name: 'Alice', seed: '//Alice' },
        { name: 'Bob', seed: '//Bob' },
        { name: 'Charlie', seed: '//Charlie' },
    ];

    const results = [];
    for (const user of usersToCreate) {
        try {
            const result = await createDidForUser(api, submitter, user.name, user.seed);
            results.push(result);
        } catch (error) {
            console.error(`\n❌ FAILED to create DID for ${user.name}.`);
            // We throw the error to stop the script if one fails, as the setup is sequential.
            throw error;
        }
    }

    // 3. Print the final results in a clean, copy-pasteable format.
    console.log("\n\n✅✅✅ All DIDs Created Successfully ✅✅✅");
    console.log("\nCopy the following block into your `examples/e2e-flow/_setup.ts` file:\n");
    console.log("----------------------------------------------------------------\n");

    const manager = results.find(r => r.userName === 'Alice')!;
    const admin = results.find(r => r.userName === 'Bob')!;
    const contributor = results.find(r => r.userName === 'Charlie')!;

    // Generate the text block for easy copy-pasting
    const output = `
// --- On-Chain Identifiers (AccountId) ---
export const MANAGER_ACCOUNT_ID = '${manager.accountId}';
export const ADMIN_ACCOUNT_ID = '${admin.accountId}';
export const CONTRIBUTOR_ACCOUNT_ID = '${contributor.accountId}';

// --- Off-Chain Identifiers (Full DID URI) ---
export const MANAGER_DID_URI = '${manager.didUri}';
export const ADMIN_DID_URI = '${admin.didUri}';
export const CONTRIBUTOR_DID_URI = '${contributor.didUri}';

// --- Private Key for E2E Test Decryption ---
// This is the private key for the keyAgreement key on Charlie's DID.
// Needed for Step 5 (05-reader-retrieves-skb.ts) to prove decryption works.
export const CONTRIBUTOR_PRIVATE_KEY_JWK: JWK = ${JSON.stringify(contributor.keyAgreementSecretKeyJwk, null, 2)};
`;

    console.log(output);
    console.log("\n----------------------------------------------------------------");

    // 4. Save the results to a file for easy reference
    fs.writeFileSync('./dids-and-keys.json', JSON.stringify(results, null, 2));
    console.log("\n📝 Full results also saved to `dids-and-keys.json` in your project root.");
}

main()
    .then(() => {
        console.log('\nScript finished successfully.');
        process.exit(0);
    })
    .catch((e) => {
        console.error(e);
        process.exit(1);
    })
    .finally(Kilt.disconnect);