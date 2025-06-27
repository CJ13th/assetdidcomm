// src/client.ts
import { AssetDidCommClientConfig, Signer, StorageAdapter, DidResolver } from './config'; // Assuming config.ts exists
import { ApiPromise, WsProvider } from '@polkadot/api'; // Add to imports
import { createDirectMessage } from 'message-module-js';
import { encryptJWE, calculateSha256Digest, decryptJWE } from './crypto/encryption';
import { MOCK_PKB_JWK, MOCK_SKB_JWK } from './crypto/keys'; // Using the mock PKB for now
import type { JWK } from 'jose';
import { v4 as uuidv4 } from 'uuid';


export class AssetDidCommClient {
    private config: AssetDidCommClientConfig;
    private polkadotApi?: ApiPromise; // Will be initialized if rpcEndpoint is provided

    constructor(config: AssetDidCommClientConfig) {
        if (!config.storageAdapter) {
            throw new Error("StorageAdapter is required in config.");
        }
        if (!config.didResolver) {
            throw new Error("DidResolver is required in config.");
        }
        if (!config.signer) {
            throw new Error("Signer is required in config.");
        }
        this.config = config;

        if (config.rpcEndpoint) {
            this.initializePolkadotApi(config.rpcEndpoint);
        }
    }

    private async initializePolkadotApi(rpcEndpoint: string): Promise<void> {
        const provider = new WsProvider(rpcEndpoint);
        this.polkadotApi = await ApiPromise.create({ provider });
        console.log(`Polkadot API initialized and connected to ${rpcEndpoint}`);
        this.polkadotApi.on('disconnected', () => console.warn('Polkadot API disconnected'));
        this.polkadotApi.on('error', (error) => console.error('Polkadot API error:', error));
    }

    /**
     * Sends a direct message to a recipient within a specific asset entity's bucket.
     * The message is encrypted using the bucket's public key (PKB).
     *
     * @param entityId The identifier for the asset entity.
     * @param bucketId The identifier for the bucket within the entity.
     * @param recipientDid The DID of the message recipient.
     * @param messageContent The plaintext content of the message.
     * @param tag An optional tag for the message (e.g., "chat", "update").
     * @returns A promise that resolves with the on-chain message ID (tx hash),
     *          the storage identifier (CID), and the JWE string.
     */
    public async sendDirectMessage(
        entityId: string,
        bucketId: string,
        recipientDid: string,
        messageContent: string,
        tag: string = "direct_message_v1" // Example default tag
    ): Promise<{ messageIdOnChain: string, storageIdentifier: string, jwe: string }> {
        console.log(`Attempting to send direct message to ${recipientDid} for entity ${entityId}, bucket ${bucketId}`);

        // 1. Fetch the Public Key of the Bucket (PKB)
        // For now, this is mocked. Later, it will query the Substrate pallet.
        const pkbJwk = await this.fetchBucketPublicKey(entityId, bucketId);
        if (!pkbJwk) {
            throw new Error(`Could not fetch PKB for bucket ${bucketId} under entity ${entityId}.`);
        }

        // 2. Construct Plaintext DIDComm Message (using WASM module)
        const senderDid = this.config.signer.getAddress();
        const messageId = uuidv4(); // Generate a unique ID for the DIDComm message
        const createdTime = Math.floor(Date.now() / 1000);

        let didCommMsgString: string;
        try {
            didCommMsgString = createDirectMessage({ // This function is from your WASM binding
                id: messageId,
                to: [recipientDid],
                from: senderDid,
                createdTime: createdTime, // Ensure your WASM options match this field name if used
                message: messageContent,
                // lang: "en", // Optional, add if your WASM builder supports it
            });
        } catch (e) {
            console.error("Error creating DIDComm message via WASM:", e);
            throw new Error("Failed to construct DIDComm message.");
        }

        const didCommMsgObject = JSON.parse(didCommMsgString);
        console.log("Constructed Plaintext DIDComm Message:", didCommMsgObject);
        const plaintextBytes = new TextEncoder().encode(JSON.stringify(didCommMsgObject));

        // 3. Encrypt the DIDComm Message using JWE with PKB
        let jweString: string;
        try {
            jweString = await encryptJWE(plaintextBytes, pkbJwk);
        } catch (e) {
            console.error("Error encrypting JWE:", e);
            throw new Error("Failed to encrypt message for bucket.");
        }
        console.log("Encrypted JWE:", jweString);

        // 4. Upload Encrypted JWE to Storage
        // The storage adapter should handle Uint8Array or string appropriately.
        // Storing the JWE string directly is fine.
        const encryptedPayloadForStorage = new TextEncoder().encode(jweString);
        let storageIdentifier: string;
        try {
            storageIdentifier = await this.config.storageAdapter.upload(encryptedPayloadForStorage);
        } catch (e) {
            console.error("Error uploading to storage:", e);
            throw new Error("Failed to upload encrypted message to storage.");
        }
        console.log(`Encrypted message stored at: ${storageIdentifier}`);

        // 5. Calculate Digest of the JWE for on-chain integrity check
        const digestHex = await calculateSha256Digest(jweString);
        console.log(`Digest of JWE (for pallet): ${digestHex}`);

        // 6. Submit Message Reference and Metadata to Substrate Pallet (Mocked for now)
        const palletMessageData = {
            reference: storageIdentifier, // This is the CID or URL from storage
            digest: digestHex,            // Hash of the JWE content
            tag: tag,
            // contributor: senderDid, // Pallet might get this from tx origin
        };

        let messageIdOnChain: string;
        try {
            messageIdOnChain = await this.submitToPallet(entityId, bucketId, palletMessageData);
        } catch (e) {
            console.error("Error submitting to pallet:", e);
            // Potentially try to remove from storage if pallet submission fails? Complex.
            throw new Error("Failed to submit message metadata to the blockchain.");
        }
        console.log(`Message metadata submitted to pallet. On-chain ID/TxHash: ${messageIdOnChain}`);

        return { messageIdOnChain, storageIdentifier, jwe: jweString };
    }

    /**
     * Fetches the Public Key of the Bucket (PKB).
     * @param entityId The ID of the entity.
     * @param bucketId The ID of the bucket.
     * @returns The PKB in JWK format, or null if not found/not writable.
     */
    private async fetchBucketPublicKey(entityId: string, bucketId: string): Promise<JWK | null> {
        console.warn(`Fetching PKB for entity ${entityId}, bucket ${bucketId} - MOCK IMPLEMENTATION`);
        // TODO: Implement actual pallet query
        // Example (pseudo-code for pallet query):
        // if (!this.polkadotApi) {
        //   console.error("Polkadot API not initialized. Cannot fetch PKB.");
        //   return null;
        // }
        // try {
        //   const bucketInfoRaw = await this.polkadotApi.query.didCommVault.buckets(entityId, bucketId);
        //   if (bucketInfoRaw.isNone) return null;
        //   const bucketInfo = bucketInfoRaw.unwrap();
        //   if (bucketInfo.status.isWritable) {
        //     const pkbString = bucketInfo.status.asWritable.toString(); // Or .toUtf8(), .toHex()
        //     return JSON.parse(pkbString) as JWK; // Assuming pallet stores it as a stringified JWK
        //   }
        //   return null;
        // } catch (error) {
        //   console.error(`Error fetching PKB from pallet for ${entityId}/${bucketId}:`, error);
        //   return null;
        // }
        return MOCK_PKB_JWK; // Return our hardcoded mock key for now
    }

    /**
     * Submits message metadata to the Substrate pallet.
     * @param entityId The ID of the entity.
     * @param bucketId The ID of the bucket.
     * @param messageData The metadata to submit (reference, digest, tag).
     * @returns The transaction hash or an on-chain identifier for the message.
     */
    private async submitToPallet(
        entityId: string,
        bucketId: string,
        messageData: { reference: string; digest: string; tag: string }
    ): Promise<string> {
        console.warn(
            `Submitting to pallet for entity ${entityId}, bucket ${bucketId} with data:`,
            JSON.stringify(messageData),
            "- MOCK IMPLEMENTATION"
        );
        // TODO: Implement actual extrinsic submission using Polkadot.js API and the signer
        // const extrinsic = this.polkadotApi.tx.didCommVault.write(entityId, bucketId, messageData.reference, messageData.digest, messageData.tag);
        // const signedExtrinsic = await extrinsic.signAsync(this.config.signer.getAddress(), { signer: this.config.signer }); // Assuming signer has signPayload
        // const txHash = await signedExtrinsic.send();
        // return txHash.toHex();

        // Mocking a transaction hash
        return `0x${Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('hex')}_mock_tx`;
    }

    /**
    * Retrieves and decrypts a message from storage using its identifier (CID).
    * Assumes the message was encrypted using the bucket's key pair (PKB/SKB).
    *
    * @param entityId The identifier for the asset entity (used for context, e.g. fetching SKB).
    * @param bucketId The identifier for the bucket (used for context, e.g. fetching SKB).
    * @param storageIdentifier The CID or URL of the encrypted message in storage.
    * @returns A promise that resolves with the decrypted plaintext DIDComm message object.
    * @throws Error if download or decryption fails.
    */
    public async receiveMessageByCid(
        entityId: string,
        bucketId: string,
        storageIdentifier: string
    ): Promise<Record<string, any>> { // Return type is a generic object, could be more specific
        console.log(`Attempting to receive and decrypt message from ${storageIdentifier} for entity ${entityId}, bucket ${bucketId}`);

        // 1. Fetch the Secret Key of the Bucket (SKB)
        // For now, this is mocked. Later, this will involve secure SKB retrieval/management.
        const skbJwk = await this.fetchBucketSecretKey(entityId, bucketId);
        if (!skbJwk) {
            throw new Error(`Could not obtain SKB for bucket ${bucketId} under entity ${entityId}. Decryption not possible.`);
        }

        // 2. Download Encrypted JWE from Storage
        let encryptedPayloadBytes: Uint8Array;
        try {
            encryptedPayloadBytes = await this.config.storageAdapter.download(storageIdentifier);
        } catch (e) {
            console.error(`Error downloading message from storage (ID: ${storageIdentifier}):`, e);
            throw new Error(`Failed to download message from storage: ${storageIdentifier}`);
        }

        const jweString = new TextDecoder().decode(encryptedPayloadBytes);
        console.log("Downloaded JWE:", jweString);

        // 3. Decrypt the JWE using SKB
        let decryptedPlaintextBytes: Uint8Array;
        try {
            decryptedPlaintextBytes = await decryptJWE(jweString, skbJwk);
        } catch (e) {
            // Error already logged in decryptJWE, rethrow specific error or generic
            console.error(`Error decrypting JWE from ${storageIdentifier}:`, e);
            throw new Error(`Failed to decrypt message from ${storageIdentifier}. Ensure you have the correct secret key and the message is not corrupted.`);
        }

        // 4. Decode and Parse the Plaintext DIDComm Message
        try {
            const decryptedMessageString = new TextDecoder().decode(decryptedPlaintextBytes);
            const decryptedMessageObject = JSON.parse(decryptedMessageString);
            console.log("Successfully Decrypted Message:", decryptedMessageObject);
            return decryptedMessageObject;
        } catch (e) {
            console.error("Error parsing decrypted message content:", e);
            throw new Error("Failed to parse decrypted message. Content may be malformed.");
        }
    }

    /**
     * Fetches the Secret Key of the Bucket (SKB).
     *
     * !!! THIS IS A HIGHLY SENSITIVE OPERATION AND MOCKED FOR NOW !!!
     * In a real system, SKB is never fetched like this directly.
     * It's usually obtained by decrypting a key-sharing message specific to the user,
     * or managed by a secure enclave / wallet.
     *
     * @param entityId The ID of the entity.
     * @param bucketId The ID of the bucket.
     * @returns The SKB in JWK format, or null if not found/accessible.
     */
    private async fetchBucketSecretKey(entityId: string, bucketId: string): Promise<JWK | null> {
        console.warn(
            `Fetching SKB for entity ${entityId}, bucket ${bucketId} - MOCK IMPLEMENTATION. ` +
            `This is highly insecure for a real system. Using MOCK_SKB_JWK.`
        );
        // TODO: Implement actual secure SKB retrieval mechanism.
        // This will likely involve:
        // 1. Checking if we have a cached SKB for this bucketId.
        // 2. If not, looking for key-sharing messages in this or a parent/admin bucket.
        // 3. Decrypting a key-sharing message using the user's own private key.
        return MOCK_SKB_JWK;
    }

}