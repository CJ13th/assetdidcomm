import 'dotenv/config';
import * as fs from 'fs';
import * as Kilt from '@kiltprotocol/sdk-js';
import type { DidDocument, KiltEncryptionKeypair, KiltKeyringPair } from '@kiltprotocol/types';
import { Crypto, Multikey } from '@kiltprotocol/utils';
import type { JWK } from 'jose';

// This is the main function that creates a DID for a specific user
async function createDidForUser(
    userName: string,
    userSeed: string,
    submitterAccount: KiltKeyringPair,
    kiltApi: Kilt.KiltApi
): Promise<any> {
    console.log(`\n---\n🚀 Starting DID Creation for: ${userName} ---\n`);

    // 1. Generate the keypairs for the new DID.
    // The AUTHENTICATION key MUST be derived from the user's seed (e.g., //Alice).
    // This ensures the DID is controlled by the account address we expect.
    const authenticationKey = Crypto.makeKeypairFromUri(userSeed, 'sr25519');
    console.log(`🔑 ${userName}'s Authentication AccountId: ${authenticationKey.address}`);

    // The KEY AGREEMENT (encryption) key should be a new, separate key.
    const keyAgreementKey = Crypto.makeEncryptionKeypairFromSeed();
    console.log(`🔑 Generated Key Agreement Key for ${userName}.`);

    // 2. Create the DID creation transaction.
    // The DID is created on-chain with only the authentication key to start.
    const createDidResult = await Kilt.Did.create({
        api: kiltApi,
        submitter: submitterAccount,
        authentication: authenticationKey,
    });
    console.log(`✅ DID created on-chain for ${userName}. Waiting for finalization...`);
    await Kilt.BlockchainUtils.signAndSubmitTx(createDidResult, submitterAccount, {
        requeue: true,
        resolveOn: Kilt.BlockchainUtils.IS_FINALIZED,
    });

    // We must resolve the DID now to get its latest state before updating it.
    let didDocument = await Kilt.Did.resolve(createDidResult.did);
    if (!didDocument?.details) throw new Error(`Could not resolve DID for ${userName}`);
    console.log(`✅ DID ${didDocument.details.did} resolved successfully.`);

    // 3. Add the key agreement key to the DID.
    // This is a second transaction that updates the DID document.
    const addKeyAgreementTx = await Kilt.Did.addKeyAgreement(
        didDocument.details,
        submitterAccount,
        keyAgreementKey
    );
    console.log(`🚀 Adding Key Agreement key to ${userName}'s DID...`);
    await Kilt.BlockchainUtils.signAndSubmitTx(addKeyAgreementTx, submitterAccount, {
        requeue: true,
        resolveOn: Kilt.BlockchainUtils.IS_FINALIZED,
    });
    console.log(`✅ Key Agreement key added successfully for ${userName}.`);

    // 4. Convert the generated keyAgreementKey into JWK format for our client.
    const keyAgreementPublicKeyJwk: JWK = {
        kty: 'OKP',
        crv: 'X25519',
        use: 'enc',
        x: Buffer.from(keyAgreementKey.publicKey).toString('base64url'),
    };
    const keyAgreementSecretKeyJwk: JWK = {
        ...keyAgreementPublicKeyJwk,
        d: Buffer.from(keyAgreementKey.secretKey).toString('base64url'),
    };

    return {
        userName,
        accountId: authenticationKey.address,
        didUri: createDidResult.did,
        keyAgreementPublicKeyJwk,
        keyAgreementSecretKeyJwk,
    };
}

// This is the main execution block
async function main() {
    await Kilt.init();
    const kiltApi = Kilt.ConfigService.get('api');
    console.log('✅ Successfully connected to the KILT blockchain.');

    // 1. Set up a FUNDED account from .env to pay for all transactions.
    if (!process.env.KILT_FAUCET_SEED) {
        throw new Error("KILT_FAUCET_SEED not found in .env file. This account is required to pay for transactions.");
    }
    const submitter = Crypto.makeKeypairFromUri(process.env.KILT_FAUCET_SEED);
    console.log(`🔑 Using Submitter Account: ${submitter.address} to pay for all transactions.`);

    // 2. Define the users we want to create DIDs for.
    const usersToCreate = [
        { name: 'Alice', seed: '//Alice' },
        { name: 'Bob', seed: '//Bob' },
        { name: 'Charlie', seed: '//Charlie' },
    ];

    const results = [];
    for (const user of usersToCreate) {
        try {
            const result = await createDidForUser(user.name, user.seed, submitter, kiltApi);
            results.push(result);
        } catch (error) {
            console.error(`\n❌ FAILED to create DID for ${user.name}:`, error);
        }
    }

    // 3. Print the final results in a clean, copy-pasteable format.
    console.log("\n\n--- ✅ All DIDs Created ---");
    console.log("Copy these values into your `examples/e2e-flow/_setup.ts` file.\n");

    const setupFileContent: Record<string, string> = {};

    for (const result of results) {
        const keyName = result.userName.toUpperCase();
        console.log(`// --- ${keyName} ---`);
        console.log(`export const ${keyName}_ACCOUNT_ID = '${result.accountId}';`);
        console.log(`export const ${keyName}_DID_URI = '${result.didUri}';\n`);

        setupFileContent[`${keyName}_ACCOUNT_ID`] = result.accountId;
        setupFileContent[`${keyName}_DID_URI`] = result.didUri;

        if (result.userName === 'Charlie') {
            console.log('// Charlie\'s Private Key - Needed for Step 5 (05-reader-retrieves-skb.ts)');
            console.log('export const CONTRIBUTOR_PRIVATE_KEY_JWK =', JSON.stringify(result.keyAgreementSecretKeyJwk, null, 2), ';');
            setupFileContent['CONTRIBUTOR_PRIVATE_KEY_JWK'] = result.keyAgreementSecretKeyJwk;
        }
    }

    // 4. Save the results to a file for easy access
    fs.writeFileSync('./dids-and-keys.json', JSON.stringify(results, null, 2));
    console.log("\n✅ Full results also saved to `dids-and-keys.json` in your project root.");

    await Kilt.disconnect();
}

main()
    .then(() => console.log('\nScript finished successfully.'))
    .catch((e) => {
        console.error(e);
        process.exit(1);
    });