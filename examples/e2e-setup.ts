// Create this file at examples/full-e2e-setup.ts
import 'dotenv/config';
import { AssetDidCommClient } from '../src/client';
import { PinataStorageAdapter } from '../src/storage/pinata';
import { KeyringSigner } from '../src/signers/keyring';
import { MockDidResolver } from '../src/signers/mock'; // We'll use this for now
import { cryptoWaitReady, decodeAddress, encodeAddress } from '@polkadot/util-crypto';
import * as jose from 'jose';
import { v4 as uuidv4 } from 'uuid';
import { hexToU8a } from '@polkadot/util';
import { KiltDidResolver } from '../src/resolvers/kilt';


// --- Configuration ---
const RPC_ENDPOINT = 'wss://fraa-flashbox-4654-rpc.a.stagenet.tanssi.network';
const PINATA_JWT = process.env.PINATA_JWT;
if (!PINATA_JWT) {
    throw new Error("PINATA_JWT environment variable not set.");
}

// --- Account & DID Setup ---
// const MANAGER_SEED = 'zrv34moyfEJeVFTsiuvHZrCrG5bwsNGUSxE3yVbzzXoXuZgu2AZFEWre2427FM6CgsXcgw9YQDGzNtRBXBYGUnLdEcJ'; // Will be the Entity Manager
// const ADMIN_SEED = 'zruzi3BZvBQqt29NoLowic2UZzs1YR3NiAY1zHTojWvpCCLVcrjkcbLgsGsdmoVhGfe6TgjDAev632vQQ1pZ7AjA4qy';     // Will be the Bucket Admin
// const CONTRIBUTOR_SEED = 'zrv2qJPZScm2zP6NhGeTBqS9VH4ppdQePuDQYZQeu3ijjALgPmnwXd7E9fXZWzbfJhfv59Nn5R8Wcetcej8BrTCqgou'; // Will be a Contributor and Reader

// Using well-known dev accounts for roles
const MANAGER_SEED = '//Alice'; // Will be the Entity Manager
const ADMIN_SEED = '//Bob';     // Will be the Bucket Admin
const CONTRIBUTOR_SEED = '//Charlie'; // Will be a Contributor and Reader

const manager_DID = '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY'
const admin_DID = '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty'
const contributor_DID = '5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y'

async function main() {
    await cryptoWaitReady();
    console.log('Crypto WASM initialized.');

    if (!PINATA_JWT) {
        throw new Error("FATAL: PINATA_JWT environment variable not set.");
    }

    // --- Step 0: Initialize Clients for Each Role ---
    const managerSigner = new KeyringSigner(MANAGER_SEED);
    const adminSigner = new KeyringSigner(ADMIN_SEED);
    const contributorSigner = new KeyringSigner(CONTRIBUTOR_SEED);


    const kiltResolver = new KiltDidResolver('wss://peregrine.kilt.io/');
    await kiltResolver.connect();

    // Each user would have their own client instance
    const managerClient = new AssetDidCommClient({
        storageAdapter: new PinataStorageAdapter({ jwt: PINATA_JWT }),
        didResolver: kiltResolver,
        signer: managerSigner,
        rpcEndpoint: RPC_ENDPOINT
    });

    const adminClient = new AssetDidCommClient({
        storageAdapter: new PinataStorageAdapter({ jwt: PINATA_JWT }),
        didResolver: kiltResolver,
        signer: adminSigner,
        rpcEndpoint: RPC_ENDPOINT
    });

    const contributorClient = new AssetDidCommClient({
        storageAdapter: new PinataStorageAdapter({ jwt: PINATA_JWT }),
        didResolver: kiltResolver,
        signer: contributorSigner,
        rpcEndpoint: RPC_ENDPOINT
    });


    // --- The E2E Flow ---
    const entityId = Math.floor(Math.random() * 1_000_000_000);
    let bucketId: number;

    try {
        console.log("\n--- Connecting clients to the node ---");
        await Promise.all([
            managerClient.connect(),
            adminClient.connect(),
            contributorClient.connect()
        ]);
        console.log("All clients connected.");
        // Step 1: manager (Manager) creates an entity/namespace
        console.log(`\n--- [manager] Step 1: Creating Entity: ${entityId} ---`);
        await managerClient.createEntity(entityId, { name: "My Test Real Estate Asset" });

        // Step 2: manager (Manager) creates a bucket
        console.log(`\n--- [manager] Step 2: Creating Bucket ---`);
        const { bucketId: newBucketId } = await managerClient.createBucket(entityId, { purpose: "Document Storage" });
        bucketId = newBucketId;
        console.log(`Bucket created with ID: ${bucketId}`);

        // Step 3: manager (Manager) sets admin as an admin
        console.log(`\n--- [manager] Step 3: Setting admin as Admin ---`);
        await managerClient.addAdmin(entityId, bucketId, admin_DID);

        // Step 4: manager (manager) adds contributor as a contributor
        console.log(`\n--- [manager] Step 4: Adding contributor as Contributor ---`);
        await adminClient.addContributor(entityId, bucketId, contributor_DID);

        // Step 5: admin (Admin) generates a new key pair for the bucket
        console.log(`\n--- [admin] Step 5: Generating Bucket Keys (off-chain) ---`);
        const { publicKey, privateKey } = await jose.generateKeyPair('ECDH-ES+A256KW', { extractable: true });
        const bucketPkJwk = await jose.exportJWK(publicKey);
        const bucketSkJwk = await jose.exportJWK(privateKey);
        bucketPkJwk.kid = Math.floor(Math.random() * 1_000_000_000);
        bucketSkJwk.kid = `skb-for-bucket-${bucketId}`;
        console.log("Bucket Public Key (PKB):", bucketPkJwk);

        // Step 6: admin (Admin) updates the bucket's PKB record on-chain
        console.log(`\n--- [admin] Step 6: Setting Bucket Public Key on-chain ---`);
        await adminClient.setBucketPublicKey(entityId, bucketId, bucketPkJwk);

        // Step 7, 8, 9: admin (Admin) encrypts SKB for contributor and writes it to the bucket
        console.log(`\n--- [admin] Step 7-9: Sharing SKB with contributor (Reader) ---`);
        await adminClient.shareBucketKey(
            entityId,
            bucketId,
            { publicJwk: bucketPkJwk, secretJwk: bucketSkJwk },
            [contributor_DID]
        );

        // Step 10: contributor (Reader) fetches the message and decrypts the SKB
        console.log(`\n--- [contributor] Step 10: Retrieving and Decrypting SKB ---`);
        // We need contributor's private key for decryption. For this test, we'll generate one.
        // In a real app, contributor's wallet would manage this.
        const contributorMockPrivateKey = { kty: 'EC', crv: 'P-256', x: 'contributor_pub_x', y: 'contributor_pub_y', d: 'contributor_priv_d' };
        const retrievedSkb = await contributorClient.retrieveBucketSecretKey(bucketId, contributorMockPrivateKey);

        console.log("\n--- VERIFICATION ---");
        console.log("Original SKB:", bucketSkJwk);
        console.log("Retrieved SKB:", retrievedSkb);

        if (retrievedSkb.d === bucketSkJwk.d) {
            console.log("\n✅ SUCCESS: contributor successfully retrieved the correct bucket secret key!");
        } else {
            console.error("\n❌ FAILURE: Retrieved SKB does not match the original.");
        }

    } catch (error) {
        console.error("\nAn error occurred during the E2E flow:", error);
    } finally {
        await kiltResolver.disconnect();
        // Disconnect the clients
        console.log("\n--- Tearing down clients ---");
        await Promise.all([
            managerClient.disconnect(),
            adminClient.disconnect(),
            contributorClient.disconnect()
        ]);
    }
}

main().catch(console.error);