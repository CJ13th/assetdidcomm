import 'dotenv/config';
import * as fs from 'fs';
import * as path from 'path';
import { AssetDidCommClient } from '../../src/client';
import { PinataStorageAdapter } from '../../src/storage/pinata';
import { KeyringSigner } from '../../src/signers/keyring';
import { KiltDidResolver } from '../../src/resolvers/kilt';
import { cryptoWaitReady } from '@polkadot/util-crypto';

// --- Shared Configuration ---
export const RPC_ENDPOINT = 'wss://fraa-flashbox-4654-rpc.a.stagenet.tanssi.network';
export const KILT_ENDPOINT = 'wss://peregrine.kilt.io/';
const PINATA_JWT = process.env.PINATA_JWT;

// --- Well-known Accounts & DIDs ---
export const MANAGER_SEED = '//Alice';
export const ADMIN_SEED = '//Bob';
export const CONTRIBUTOR_SEED = '//Charlie';

// These DIDs must correspond to the seeds above and have a keyAgreement key.
// In a real scenario, you would fetch these from a user's profile or identity service.
export const MANAGER_DID = '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY'; // Example DID for Alice
export const ADMIN_DID = '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty';     // Example DID for Bob
export const CONTRIBUTOR_DID = '5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y'; // Example DID for Charlie

// --- State Management ---
const STATE_FILE_PATH = path.join(__dirname, 'e2e-state.json');

export function readState(): Record<string, any> {
    if (fs.existsSync(STATE_FILE_PATH)) {
        const fileContent = fs.readFileSync(STATE_FILE_PATH, 'utf-8');
        return JSON.parse(fileContent);
    }
    return {}; // Return empty object if file doesn't exist
}

export function writeState(newState: Record<string, any>): void {
    const currentState = readState();
    const updatedState = { ...currentState, ...newState };
    fs.writeFileSync(STATE_FILE_PATH, JSON.stringify(updatedState, null, 2));
    console.log(`✅ State updated in ${STATE_FILE_PATH}`);
}

const KEY_STATE_FILE_PATH = path.join(__dirname, 'e2e-keys.json');

export function readKeyState(): Record<string, any> {
    if (fs.existsSync(KEY_STATE_FILE_PATH)) {
        const fileContent = fs.readFileSync(KEY_STATE_FILE_PATH, 'utf-8');
        return JSON.parse(fileContent);
    }
    return {};
}

export function writeKeyState(newKeyState: Record<string, any>): void {
    const currentState = readKeyState();
    const updatedState = { ...currentState, ...newKeyState };
    fs.writeFileSync(KEY_STATE_FILE_PATH, JSON.stringify(updatedState, null, 2));
    console.log(`✅ Key state updated in ${KEY_STATE_FILE_PATH}`);
}

// --- Client Setup Function ---
export async function setup() {
    await cryptoWaitReady();
    console.log('Crypto WASM initialized.');

    if (!PINATA_JWT) {
        throw new Error("FATAL: PINATA_JWT environment variable not set.");
    }

    // Initialize one DID resolver for all clients
    const kiltResolver = new KiltDidResolver(KILT_ENDPOINT);
    await kiltResolver.connect();

    // Create a signer for each role
    const managerSigner = new KeyringSigner(MANAGER_SEED);
    const adminSigner = new KeyringSigner(ADMIN_SEED);
    const contributorSigner = new KeyringSigner(CONTRIBUTOR_SEED);

    // Create a client instance for each role
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

    // Connect all clients to the node
    console.log("\n--- Connecting clients to the node ---");
    await Promise.all([
        managerClient.connect(),
        adminClient.connect(),
        contributorClient.connect()
    ]);
    console.log("All clients connected.");

    const disconnectAll = async () => {
        console.log("\n--- Tearing down clients ---");
        await Promise.all([
            managerClient.disconnect(),
            adminClient.disconnect(),
            contributorClient.disconnect()
        ]);
        await kiltResolver.disconnect();
    };

    return {
        managerClient,
        adminClient,
        contributorClient,
        disconnectAll,
    };
}