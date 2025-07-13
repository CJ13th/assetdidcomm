// src/crypto/encryption.ts
import * as jose from 'jose';
import type { JWK } from 'jose';

// Define the JWE algorithms you'll use (as per DIDCOMM VAULT spec or your choice)
const JWE_ALG = 'ECDH-ES+A256KW';
const JWE_ENC = 'A256GCM';


/**
 * Encrypts a plaintext payload (DIDComm message) using JWE.
 * The Content Encryption Key (CEK) is encrypted using the provided public key (e.g., PKB).
 *
 * @param plaintext The plaintext to encrypt (e.g., a stringified DIDComm message).
 * @param recipientPublicKeyJwk The recipient's public key in JWK format, used to encrypt the CEK.
 * @returns The JWE as a compact serialization string.
 * @throws Error if encryption fails.
 */
export async function encryptJWE(
    plaintext: Uint8Array,
    recipientPublicKeyJwk: JWK
): Promise<string> {
    try {
        const publicKey = await jose.importJWK(recipientPublicKeyJwk, JWE_ALG); // Specify alg for import if needed

        const jwe = await new jose.CompactEncrypt(plaintext)
            .setProtectedHeader({ alg: JWE_ALG, enc: JWE_ENC })
            .encrypt(publicKey);

        return jwe;
    } catch (error) {
        console.error('JWE Encryption failed:', error);
        // It's often good to throw a more specific error or wrap the original
        if (error instanceof Error) {
            throw new Error(`Failed to encrypt message: ${error.message}`);
        }
        throw new Error('Failed to encrypt message due to an unknown error.');
    }
}

/**
 * Generates a SHA-256 digest of the input data.
 * @param data The data to hash.
 * @returns The hex-encoded SHA-256 digest.
 */
export async function calculateSha256Digest(data: string | Uint8Array): Promise<string> {
    const dataBuffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
    return hashHex;
}


/**
 * Decrypts a JWE compact serialization string.
 *
 * @param jweCompact The JWE compact serialization string.
 * @param privateKeyJwk The recipient's private key in JWK format, used to decrypt the CEK.
 * @returns The decrypted plaintext as a Uint8Array.
 * @throws Error if decryption fails.
 */
export async function decryptJWE(
    jweCompact: string,
    privateKeyJwk: JWK
): Promise<Uint8Array> {
    try {
        // 1. Import the private JWK to a format jose can use for decryption
        //    The algorithm 'ECDH-ES+A256KW' (or whatever JWE_ALG is) needs to be known by importJWK
        //    to correctly interpret the key.
        const privateKey = await jose.importJWK(privateKeyJwk, JWE_ALG);

        // 2. Perform JWE Decryption
        const { plaintext, protectedHeader } = await jose.compactDecrypt(jweCompact, privateKey);

        // Optional: Verify protected header if needed (e.g., check 'alg' and 'enc')
        // console.log('Decrypted with protected header:', protectedHeader);
        // if (protectedHeader.alg !== JWE_ALG || protectedHeader.enc !== JWE_ENC) {
        //   throw new Error('JWE header validation failed: Unexpected algorithm or encoding.');
        // }

        return plaintext; // This is a Uint8Array
    } catch (error) {
        console.error('JWE Decryption failed:', error);
        if (error instanceof Error) {
            // Provide more specific error messages if possible based on jose error types
            if (error.name === 'JWEDecryptionFailed') {
                throw new Error('Failed to decrypt message: Integrity check failed or key mismatch.');
            } else if (error.name === 'JWKImportFailed') {
                throw new Error('Failed to decrypt message: Invalid private key format.');
            }
            throw new Error(`Failed to decrypt message: ${error.message}`);
        }
        throw new Error('Failed to decrypt message due to an unknown error.');
    }
}



/**
 * Encrypts a plaintext payload for multiple recipients using General JWE JSON Serialization.
 * This is used for key-sharing messages.
 *
 * @param plaintext The plaintext to encrypt.
 * @param recipientPublicKeys An array of recipient public keys in JWK format.
 * @returns The JWE as a JSON object (General JWE Serialization).
 * @throws Error if encryption fails.
 */
export async function encryptJWEForMultipleRecipients(
    plaintext: Uint8Array,
    recipientPublicKeys: JWK[]
): Promise<jose.GeneralJWE> {
    try {
        const generalEncrypt = new jose.GeneralEncrypt(plaintext);
        generalEncrypt.setProtectedHeader({ alg: JWE_ALG, enc: JWE_ENC });

        for (const jwk of recipientPublicKeys) {
            const publicKey = await jose.importJWK(jwk, JWE_ALG);
            generalEncrypt.addRecipient(publicKey);
        }

        return await generalEncrypt.encrypt();
    } catch (error) {
        console.error('General JWE Encryption failed:', error);
        if (error instanceof Error) {
            throw new Error(`Failed to encrypt message for multiple recipients: ${error.message}`);
        }
        throw new Error('Failed to encrypt message for multiple recipients due to an unknown error.');
    }
}

// You will also need a corresponding decryption function
/**
 * Decrypts a General JWE JSON Serialization object.
 *
 * @param jwe The General JWE object.
 * @param privateKeyJwk The recipient's private key in JWK format.
 * @returns The decrypted plaintext as a Uint8Array.
 * @throws Error if decryption fails.
 */
export async function decryptGeneralJWE(
    jwe: jose.GeneralJWE,
    privateKeyJwk: JWK
): Promise<Uint8Array> {
    try {
        const privateKey = await jose.importJWK(privateKeyJwk, "ECDH-ES");
        const { plaintext } = await jose.generalDecrypt(jwe, privateKey);
        return plaintext;
    } catch (error) {
        console.error('General JWE Decryption failed:', error);
        if (error instanceof Error) {
            throw new Error(`Failed to decrypt general JWE message: ${error.message}`);
        }
        throw new Error('Failed to decrypt general JWE message due to an unknown error.');
    }
}