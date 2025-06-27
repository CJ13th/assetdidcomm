// Create this file at examples/full-e2e-setup.ts
import 'dotenv/config';
import { AssetDidCommClient } from '../src/client';
import { PinataStorageAdapter } from '../src/storage/pinata';
import { KeyringSigner } from '../src/signers/keyring';
import { MockDidResolver } from '../src/signers/mock'; // We'll use this for now
import { cryptoWaitReady } from '@polkadot/util-crypto';
import * as jose from 'jose';
import { v4 as uuidv4 } from 'uuid';

// --- Configuration ---
const RPC_ENDPOINT = 'wss://fraa-flashbox-4654-rpc.a.stagenet.tanssi.network';
const PINATA_JWT = process.env.PINATA_JWT;
if (!PINATA_JWT) {
    throw new Error("PINATA_JWT environment variable not set.");
}

// --- Account & DID Setup ---
// Using well-known dev accounts for roles
const ALICE_SEED = '//Alice'; // Will be the Entity Manager
const BOB_SEED = '//Bob';     // Will be the Bucket Admin
const CHARLIE_SEED = '//Charlie'; // Will be a Contributor and Reader

const ALICE_DID = 'did:example:alice';
const BOB_DID = 'did:example:bob';
const CHARLIE_DID = 'did:example:charlie';


async function main() {
    await cryptoWaitReady();
    console.log('Crypto WASM initialized.');

    if (!PINATA_JWT) {
        throw new Error("FATAL: PINATA_JWT environment variable not set.");
    }

    // --- Step 0: Initialize Clients for Each Role ---
    const aliceSigner = new KeyringSigner(ALICE_SEED);
    const bobSigner = new KeyringSigner(BOB_SEED);
    const charlieSigner = new KeyringSigner(CHARLIE_SEED);

    // Each user would have their own client instance
    const aliceClient = new AssetDidCommClient({
        storageAdapter: new PinataStorageAdapter({ jwt: PINATA_JWT }),
        didResolver: new MockDidResolver(),
        signer: aliceSigner,
        rpcEndpoint: RPC_ENDPOINT
    });

    const bobClient = new AssetDidCommClient({
        storageAdapter: new PinataStorageAdapter({ jwt: PINATA_JWT }),
        didResolver: new MockDidResolver(),
        signer: bobSigner,
        rpcEndpoint: RPC_ENDPOINT
    });

    const charlieClient = new AssetDidCommClient({
        storageAdapter: new PinataStorageAdapter({ jwt: PINATA_JWT }),
        didResolver: new MockDidResolver(),
        signer: charlieSigner,
        rpcEndpoint: RPC_ENDPOINT
    });


    // --- The E2E Flow ---
    const entityId = Math.floor(Math.random() * 1_000_000_000);
    let bucketId: number;

    try {
        console.log("\n--- Connecting clients to the node ---");
        await Promise.all([
            aliceClient.connect(),
            bobClient.connect(),
            charlieClient.connect()
        ]);
        console.log("All clients connected.");
        // Step 1: Alice (Manager) creates an entity/namespace
        console.log(`\n--- [Alice] Step 1: Creating Entity: ${entityId} ---`);
        await aliceClient.createEntity(entityId, { name: "My Test Real Estate Asset" });

        // Step 2: Alice (Manager) creates a bucket
        console.log(`\n--- [Alice] Step 2: Creating Bucket ---`);
        const { bucketId: newBucketId } = await aliceClient.createBucket(entityId, { purpose: "Document Storage" });
        bucketId = newBucketId;
        console.log(`Bucket created with ID: ${bucketId}`);

        // Step 3: Alice (Manager) sets Bob as an admin
        console.log(`\n--- [Alice] Step 3: Setting Bob as Admin ---`);
        await aliceClient.addAdmin(entityId, bucketId, BOB_DID);

        // Step 4: Bob (Admin) adds Charlie as a contributor
        console.log(`\n--- [Bob] Step 4: Adding Charlie as Contributor ---`);
        await bobClient.addContributor(entityId, bucketId, CHARLIE_DID);

        // Step 5: Bob (Admin) generates a new key pair for the bucket
        console.log(`\n--- [Bob] Step 5: Generating Bucket Keys (off-chain) ---`);
        const { publicKey, privateKey } = await jose.generateKeyPair('ECDH-ES+A256KW', { extractable: true });
        const bucketPkJwk = await jose.exportJWK(publicKey);
        const bucketSkJwk = await jose.exportJWK(privateKey);
        bucketPkJwk.kid = `pkb-for-bucket-${bucketId}`;
        bucketSkJwk.kid = `skb-for-bucket-${bucketId}`;
        console.log("Bucket Public Key (PKB):", bucketPkJwk);

        // Step 6: Bob (Admin) updates the bucket's PKB record on-chain
        console.log(`\n--- [Bob] Step 6: Setting Bucket Public Key on-chain ---`);
        await bobClient.setBucketPublicKey(entityId, bucketId, bucketPkJwk);

        // Step 7, 8, 9: Bob (Admin) encrypts SKB for Charlie and writes it to the bucket
        console.log(`\n--- [Bob] Step 7-9: Sharing SKB with Charlie (Reader) ---`);
        await bobClient.shareBucketKey(
            entityId,
            bucketId,
            { publicJwk: bucketPkJwk, secretJwk: bucketSkJwk },
            [CHARLIE_DID]
        );

        // Step 10: Charlie (Reader) fetches the message and decrypts the SKB
        console.log(`\n--- [Charlie] Step 10: Retrieving and Decrypting SKB ---`);
        // We need Charlie's private key for decryption. For this test, we'll generate one.
        // In a real app, Charlie's wallet would manage this.
        const charlieMockPrivateKey = { kty: 'EC', crv: 'P-256', x: 'charlie_pub_x', y: 'charlie_pub_y', d: 'charlie_priv_d' };
        const retrievedSkb = await charlieClient.retrieveBucketSecretKey(bucketId, charlieMockPrivateKey);

        console.log("\n--- VERIFICATION ---");
        console.log("Original SKB:", bucketSkJwk);
        console.log("Retrieved SKB:", retrievedSkb);

        if (retrievedSkb.d === bucketSkJwk.d) {
            console.log("\n✅ SUCCESS: Charlie successfully retrieved the correct bucket secret key!");
        } else {
            console.error("\n❌ FAILURE: Retrieved SKB does not match the original.");
        }

    } catch (error) {
        console.error("\nAn error occurred during the E2E flow:", error);
    } finally {
        // Disconnect the clients
        console.log("\n--- Tearing down clients ---");
        await Promise.all([
            aliceClient.disconnect(),
            bobClient.disconnect(),
            charlieClient.disconnect()
        ]);
    }
}

main().catch(console.error);