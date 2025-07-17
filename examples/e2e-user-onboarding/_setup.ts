import 'dotenv/config';
import * as fs from 'fs';
import * as path from 'path';
import { Keyring } from '@polkadot/keyring';
import { blake2AsU8a, cryptoWaitReady } from '@polkadot/util-crypto';
import { u8aToHex, stringToU8a } from '@polkadot/util';
import nacl from 'tweetnacl';
import * as jose from 'jose';

// --- Shared Configuration ---
export const USER_SEED = '//Dave';
export const USER_DID = 'did:kilt:4r33sS12345sS12345sS12345sS12345sS12345sS12345tbaAbB'; // Example DID for Dave
export const APP_NAME = "MySecureApp";
export const SIGNING_MESSAGE = `Create secure key for ${APP_NAME}`;

// --- State Management ---
const STATE_FILE_PATH = path.join(__dirname, 'user-state.json');
const BACKUP_FILE_PATH = path.join(__dirname, 'user-backup.json');

export function readState(): Record<string, any> {
    if (fs.existsSync(STATE_FILE_PATH)) {
        const fileContent = fs.readFileSync(STATE_FILE_PATH, 'utf-8');
        return JSON.parse(fileContent);
    }
    return {};
}

export function writeState(newState: Record<string, any>): void {
    const currentState = readState();
    const updatedState = { ...currentState, ...newState };
    fs.writeFileSync(STATE_FILE_PATH, JSON.stringify(updatedState, null, 2));
    console.log(`✅ State updated in ${STATE_FILE_PATH}`);
}

export function writeBackup(backupData: Record<string, any>): void {
    fs.writeFileSync(BACKUP_FILE_PATH, JSON.stringify(backupData, null, 2));
    console.log(`✅ Backup data written to ${BACKUP_FILE_PATH}`);
}

export function readBackup(): Record<string, any> {
    if (fs.existsSync(BACKUP_FILE_PATH)) {
        const fileContent = fs.readFileSync(BACKUP_FILE_PATH, 'utf-8');
        return JSON.parse(fileContent);
    }
    throw new Error('Backup file not found!');
}

/**
 * Derives a deterministic x25519 keypair from a wallet signature.
 * This is the core function from your original script.
 */
export function makeEncryptionKeypairFromSignature(signature: Uint8Array) {
    const seed = blake2AsU8a(signature, 256); // Use the full 256-bit hash as the seed
    const keyPair = nacl.box.keyPair.fromSecretKey(seed);

    return {
        ...keyPair,
        type: 'x25519',
    };
}

/**
 * Encrypts a private key (Uint8Array) using a password.
 * Uses PBES2 for key derivation and AES-GCM for encryption via JOSE.
 */
export async function encryptKeyWithPassword(secretKey: Uint8Array, password: string): Promise<string> {
    const encoder = new TextEncoder();
    const jwe = await new jose.CompactEncrypt(
        encoder.encode(u8aToHex(secretKey))
    ).setProtectedHeader({
        alg: 'PBES2-HS256+A128KW',
        enc: 'A256GCM'
    }).encrypt(encoder.encode(password));

    return jwe;
}

/**
 * Decrypts a JWE string back into a private key (Uint8Array) using a password.
 */
export async function decryptKeyWithPassword(jwe: string, password: string): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    const { plaintext } = await jose.compactDecrypt(jwe, encoder.encode(password));
    const hexKey = new TextDecoder().decode(plaintext);
    // Convert hex back to Uint8Array
    return Uint8Array.from(Buffer.from(hexKey.startsWith('0x') ? hexKey.slice(2) : hexKey, 'hex'));
}


/**
 * Mocks publishing the public key to a DID document.
 * In this e2e test, it just saves the key to our state file.
 */
export function publishPublicKeyToDid(did: string, publicKeyHex: string): void {
    console.log(`\n--- [MOCK] Publishing Public Key to DID: ${did} ---`);
    writeState({ didPublicKey: publicKeyHex });
    console.log('✅ Mock DID update successful.');
}

/**
 * Mocks fetching the public key from a DID document.
 * In this e2e test, it just reads the key from our state file.
 */
export function fetchPublicKeyFromDid(did: string): string {
    console.log(`\n--- [MOCK] Fetching Public Key from DID: ${did} ---`);
    const state = readState();
    if (!state.didPublicKey) {
        throw new Error("No public key found in mock DID state.");
    }
    console.log('✅ Mock DID fetch successful.');
    return state.didPublicKey;
}

export async function setup() {
    await cryptoWaitReady();
    const keyring = new Keyring({ type: 'sr25519' });
    const user = keyring.addFromUri(USER_SEED);
    return { user };
}