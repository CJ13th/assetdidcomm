// src/client.ts
import * as fs from 'fs';
import type { Option } from '@polkadot/types';
import { AssetDidCommClientConfig, Signer, StorageAdapter, DidResolver } from './config'; // Assuming config.ts exists
import { ApiPromise, WsProvider } from '@polkadot/api'; // Add to imports
import type { SubmittableExtrinsic } from '@polkadot/api/types';
import type { ISubmittableResult, IEventRecord, IEvent } from '@polkadot/types/types';
import type { ResolutionResult, Did, DidDocument } from '@kiltprotocol/types';

import { createDirectMessage } from 'message-module-js';
import { encryptJWE, calculateSha256Digest, decryptJWE } from './crypto/encryption';
import { createKeySharingMessage } from 'message-module-js';
import { encryptJWEForMultipleRecipients, decryptGeneralJWE } from './crypto/encryption';
import { MOCK_PKB_JWK, MOCK_SKB_JWK } from './crypto/keys'; // Using the mock PKB for now
import type { JWK } from 'jose';
import { v4 as uuidv4 } from 'uuid';
import { KeyringSigner } from './signers/keyring';


interface OnChainMetadata {
    // The SHA-256 digest of the JWE message, hex-encoded
    digest: string;
    // Optional: any other metadata to include
    contentType?: string;
}


export class AssetDidCommClient {
    private config: AssetDidCommClientConfig;
    public polkadotApi?: ApiPromise;
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

    }

    public async connect(): Promise<void> {
        if (this.polkadotApi && this.polkadotApi.isConnected) {
            console.log("Polkadot API is already connected.");
            return;
        }

        if (!this.config.rpcEndpoint) {
            throw new Error("Cannot connect: rpcEndpoint is not configured.");
        }

        const provider = new WsProvider(this.config.rpcEndpoint);
        this.polkadotApi = await ApiPromise.create({ provider });

        console.log(`Polkadot API initialized and connected to ${this.config.rpcEndpoint} for signer ${this.config.signer.getAddress()}`);

        this.polkadotApi.on('disconnected', () => console.warn(`API disconnected for ${this.config.signer.getAddress()}`));
        this.polkadotApi.on('error', (error) => console.error(`API error for ${this.config.signer.getAddress()}:`, error));
    }

    public async disconnect(): Promise<void> {
        if (this.polkadotApi && this.polkadotApi.isConnected) {
            await this.polkadotApi.disconnect();
            console.log(`API disconnected for ${this.config.signer.getAddress()}`);
        }
    }

    /**
     * A generic helper to submit an extrinsic and wait for a specific event.
     *
     * @param extrinsic The SubmittableExtrinsic to send.
     * @param eventFinder A function that takes an event and returns true if it's the one we're looking for.
     * @param eventValidator A function that validates the found event's data and returns true if it's the correct instance.
     * @returns A promise that resolves with the found event and the transaction hash.
     * @template T - The expected type of the data extracted from the event.
     */
    private _submitAndWatch<T>( // Removed async from the function signature
        extrinsic: SubmittableExtrinsic<'promise'>,
        eventFinder: (event: IEvent<any>) => boolean,
        eventValidator: (event: IEventRecord<any>) => T | null
    ): Promise<{ data: T; txHash: string }> {
        if (!this.polkadotApi) {
            return Promise.reject(new Error("Polkadot API not initialized."));
        }
        if (!(this.config.signer instanceof KeyringSigner)) {
            return Promise.reject(new Error("This operation currently requires a KeyringSigner."));
        }
        const keypair = this.config.signer.getKeypair();

        return new Promise(async (resolve, reject) => {
            try {
                const unsubscribe = await extrinsic.signAndSend(keypair, (result: any) => {
                    console.log(`Transaction status: ${result.status.type}`);

                    if (result.status.isInBlock || result.status.isFinalized) {
                        const foundEvent = result.events.find(({ event }) => eventFinder(event));

                        if (foundEvent) {
                            const validatedData = eventValidator(foundEvent);
                            if (validatedData !== null) {
                                console.log(`✅ Event found and validated: ${foundEvent.event.section}.${foundEvent.event.method}`);
                                unsubscribe();
                                resolve({
                                    data: validatedData,
                                    txHash: result.txHash.toHex(),
                                });
                                return;
                            }
                        }

                        if (result.status.isFinalized) {
                            console.log(`Blockhash: ${result.status.asFinalized}`);
                            unsubscribe();
                            // If it finalizes without our event, something went wrong.
                            reject(new Error("Transaction finalized, but the expected event was not found or was invalid."));
                        }
                    } else if (result.isError) {
                        let errorMessage = "Transaction submission error.";
                        if (result.dispatchError?.isModule) {
                            const decoded = this.polkadotApi!.registry.findMetaError(result.dispatchError.asModule);
                            errorMessage = `Transaction failed: ${decoded?.name} - ${decoded?.docs.join(' ')}`;
                        }
                        unsubscribe();
                        reject(new Error(errorMessage));
                    }
                });
            } catch (error) {
                reject(error);
            }
        });
    }



    /**
     * Creates a new Entity (Namespace) on the chain.
     * The transaction is signed by the client's configured signer, who becomes the initial manager.
     * @param entityId The unique identifier for the new entity.
     * @param metadata An object representing the entity's metadata.
     * @returns The transaction hash.
     */
    public async createEntity(entityId: number, metadata: object = {}): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        const extrinsic = this.polkadotApi.tx.buckets.createNamespace(entityId, metadata);

        const { txHash } = await this._submitAndWatch<{ namespaceId: string }>(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.NamespaceCreated.is(event),
            (eventRecord) => {
                const [eventNamespaceId] = eventRecord.event.data;
                if ((eventNamespaceId as any).toNumber() === entityId) {
                    return { namespaceId: (eventNamespaceId as any).toNumber() };
                }
                return null; // Validation failed
            }
        );

        return txHash;
    }

    /**
     * Creates a new Bucket within an existing Entity.
     * The transaction is signed by a manager of the entity.
     * @param entityId The ID of the parent entity.
     * @param metadata An object representing the bucket's metadata.
     * @returns The transaction hash and the new bucket's ID.
     */
    public async createBucket(entityId: number, metadata: object = {}): Promise<{ txHash: string, bucketId: number }> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        const extrinsic = this.polkadotApi.tx.buckets.createBucket(entityId, metadata);

        const { data, txHash } = await this._submitAndWatch<{ bucketId: number }>(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.BucketCreated.is(event),
            (eventRecord) => {
                const [eventNamespaceId, eventBucketId] = eventRecord.event.data;
                if ((eventNamespaceId as any).toNumber() === entityId) {
                    return { bucketId: (eventBucketId as any).toNumber() };
                }
                return null; // Validation failed
            }
        );

        return { txHash, bucketId: data.bucketId };
    }

    /**
     * Sets or rotates the public key ID (PKB's ID) for a bucket, making it writable.
     * Must be called by an Admin of the bucket.
     * @param entityId The ID of the parent entity.
     * @param bucketId The ID of the bucket.
     * @param keyId The numeric ID (`u128`) of the new public key. The full key must be discoverable off-chain.
     * @returns The transaction hash.
     */
    public async setBucketPublicKey(entityId: number, bucketId: number, keyId: number): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        // The pallet's `resumeWriting` extrinsic expects the numeric keyId directly.
        const extrinsic = this.polkadotApi.tx.buckets.resumeWriting(entityId, bucketId, keyId);

        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.BucketWritableWithKey.is(event),
            (eventRecord) => {
                const [, eventBucketId, eventKeyId] = eventRecord.event.data;
                // Verify that the on-chain event matches the keyId we sent.
                if ((eventBucketId as any).toNumber() === bucketId && (eventKeyId as any).toNumber() === keyId) {
                    return { success: true };
                }
                return null;
            }
        );
        return txHash;
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
        entityId: number,
        bucketId: number,
        recipientDid: string,
        messageContent: string,
        tag: string = "direct_message_v1" // Example default tag
    ): Promise<{ messageIdOnChain: string, storageIdentifier: string, jwe: string }> {
        console.log(`Attempting to send direct message to ${recipientDid} for entity ${entityId}, bucket ${bucketId}`);

        // 1. Fetch the Public Key of the Bucket (PKB)
        const pkbJwk = await this.fetchBucketPublicKey(entityId, bucketId);
        if (!pkbJwk) {
            throw new Error(`Could not fetch PKB for bucket ${bucketId} under entity ${entityId}.`);
        }

        // 2. Construct Plaintext DIDComm Message (using WASM module)
        const senderDid = this.config.signer.getAddress();
        const messageId = uuidv4();
        const createdTime = Math.floor(Date.now() / 1000);

        let didCommMsgString: string;
        try {
            didCommMsgString = createDirectMessage({
                id: messageId,
                to: [recipientDid],
                from: senderDid,
                createdTime: createdTime,
                message: messageContent,
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
        const encryptedPayloadForStorage = new TextEncoder().encode(jweString);
        let storageIdentifier: string;
        try {
            storageIdentifier = await this.config.storageAdapter.upload(encryptedPayloadForStorage);
        } catch (e) {
            console.error("Error uploading to storage:", e);
            throw new Error("Failed to upload encrypted message to storage.");
        }
        console.log(`Encrypted message stored at: ${storageIdentifier}`);

        // 5. Calculate Digest and construct the new metadata object
        const digestHex = await calculateSha256Digest(jweString);
        console.log(`Digest of JWE (to be stored in metadata): ${digestHex}`);

        // NEW: The digest is now part of this structured metadata object.
        const metadataObject: OnChainMetadata = {
            digest: digestHex,
            contentType: 'application/didcomm+json'
        };

        // 6. Submit Message Reference and the new metadata to Substrate Pallet
        const palletMessageData = {
            reference: storageIdentifier,
            tag: tag,
            // CHANGED: We now pass the entire metadata object.
            metadata: metadataObject,
        };

        let messageIdOnChain: string;
        try {
            // The call to submitToPallet is now updated with the new payload structure
            messageIdOnChain = await this.submitToPallet(entityId, bucketId, palletMessageData);
        } catch (e) {
            console.error("Error submitting to pallet:", e);
            throw new Error("Failed to submit message metadata to the blockchain.");
        }
        console.log(`Message metadata submitted to pallet. On-chain ID/TxHash: ${messageIdOnChain}`);

        return { messageIdOnChain, storageIdentifier, jwe: jweString };
    }

    /**
    * Fetches the Public Key of the Bucket (PKB) by first getting its ID from the pallet,
    * then resolving the full key from an off-chain source.
    *
    * @param entityId The ID of the entity.
    * @param bucketId The ID of the bucket.
    * @returns The PKB in JWK format, or null if not found/not writable.
    */
    private async fetchBucketPublicKey(entityId: number, bucketId: number): Promise<JWK | null> {
        console.log(`Fetching PKB for entity ${entityId}, bucket ${bucketId}...`);
        if (!this.polkadotApi) {
            console.error("Polkadot API not initialized. Cannot fetch PKB.");
            return null;
        }

        // 1. Query the pallet to get the bucket's status and key ID.
        const bucketInfoRaw = await this.polkadotApi.query.buckets.buckets(entityId, bucketId) as unknown as Option<any>;
        if (bucketInfoRaw.isNone) {
            console.error(`Bucket ${bucketId} not found in namespace ${entityId}.`);
            return null;
        }

        const bucketInfo = bucketInfoRaw.unwrap();
        if (bucketInfo.status.isWritable) {
            const keyId = bucketInfo.status.asWritable.toNumber();
            console.log(`Bucket is writable with keyId: ${keyId}. Now resolving off-chain...`);

            // 2. Resolve the keyId to a full JWK using our file-based discovery for the E2E test.
            // In a real system, this would be a call to a DID resolver or a dedicated key discovery service.
            try {
                // This assumes the test scripts are run from the project root.
                // A more robust solution might use relative paths or environment variables.
                const keyStateContent = fs.readFileSync('./examples/e2e-flow/e2e-keys.json', 'utf-8');
                const keyState = JSON.parse(keyStateContent);
                const publicKeyJwk = keyState[keyId];

                if (!publicKeyJwk) {
                    throw new Error(`Key ID ${keyId} not found in e2e-keys.json.`);
                }
                console.log(`✅ Successfully resolved keyId ${keyId} to a JWK.`);
                return publicKeyJwk as JWK;

            } catch (error) {
                console.error(`Error resolving keyId ${keyId} from off-chain store:`, error);
                return null;
            }

        } else {
            console.warn(`Bucket ${bucketId} is locked. No public key available.`);
            return null;
        }
    }


    private async submitToPallet(
        entityId: number,
        bucketId: number,
        // CHANGED: The signature now expects our structured OnChainMetadata object.
        messageData: { reference: string; tag: string; metadata: OnChainMetadata }
    ): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        // This object must precisely match the pallet's `MessageInput` struct.
        const messageInput = {
            reference: messageData.reference,
            // The pallet expects an Option<Tag>, so we pass the tag or null.
            tag: messageData.tag || null,
            // The API will encode this string into a Vec<u8> for the pallet.
            metadata_input: JSON.stringify(messageData.metadata)
        };

        const extrinsic = this.polkadotApi.tx.buckets.write(entityId, bucketId, messageInput);

        // This part remains unchanged as it correctly handles submission and event watching.
        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.NewMessage.is(event),
            (eventRecord) => {
                const [eventBucketId] = eventRecord.event.data;
                if ((eventBucketId as any).toNumber() === bucketId) {
                    return { success: true };
                }
                return null;
            }
        );
        return txHash;
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
        entityId: number,
        bucketId: number,
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
    private async fetchBucketSecretKey(entityId: number, bucketId: number): Promise<JWK | null> {
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

    /**
     * Creates and distributes a bucket's secret key (SKB) to a list of readers.
     * This creates a special key-sharing message, encrypts it for all readers
     * (and the bucket's own new public key), and writes it to the bucket.
     *
     * @param entityId The parent entity ID.
     * @param bucketId The bucket ID.
     * @param bucketKeys The key pair (PKB/SKB) for the bucket.
     * @param readerDids A list of DIDs for the users who should receive the key.
     * @returns The on-chain message ID (tx hash) and the storage identifier (CID).
     */
    public async shareBucketKey(
        entityId: number,
        bucketId: number,
        bucketKeys: { publicJwk: JWK, secretJwk: JWK },
        readerDids: Did[] | string[]
    ): Promise<any> {
        console.log(`Sharing bucket key for bucket ${bucketId} with ${readerDids.length} readers.`);

        const skbForWasm = bucketKeys.secretJwk;
        if (!skbForWasm.kty || !skbForWasm.crv || !skbForWasm.x || !skbForWasm.y || !skbForWasm.d || !skbForWasm.use) {
            throw new Error("The generated secret JWK is missing required properties.");
        }

        const wasmCompatibleKey = {
            kty: skbForWasm.kty,
            crv: skbForWasm.crv,
            x: skbForWasm.x,
            y: skbForWasm.y,
            d: skbForWasm.d,
            use: skbForWasm.use, // Correctly map 'use' to '_use'
            kid: skbForWasm.kid || `skb-for-bucket-${bucketId}`,
        };

        // 1. Create the DIDComm Key-Sharing Message (using WASM module)
        const keySharingMsgString = createKeySharingMessage({
            id: uuidv4(),
            from: this.config.signer.getAddress(),
            to: readerDids,
            keys: [
                wasmCompatibleKey
            ]
        });
        const keySharingMsgObject = JSON.parse(keySharingMsgString);
        const plaintextBytes = new TextEncoder().encode(JSON.stringify(keySharingMsgObject));
        console.log("Constructed Key-Sharing Message:", keySharingMsgObject);

        // 2. Resolve Reader DIDs to get their public keys for encryption
        const recipientKeys: JWK[] = [bucketKeys.publicJwk]; // Bucket can always decrypt its own key messages
        for (const did of readerDids) {
            console.log(`Resolving DID for reader: ${did}`);
            const resolutionResult = await this.config.didResolver.resolve(did as Did); // Use the configured resolver

            const didDocument = resolutionResult.didDocument;
            didDocument?.verificationMethod[0].publicKeyMultibase

            if (!didDocument || !didDocument.keyAgreement || didDocument.keyAgreement.length === 0) {
                console.warn(`Could not find a valid keyAgreement key for DID: ${did}. Skipping.`);
                continue;
            }
            const keyAgreementEntry = didDocument.keyAgreement.find(
                (key: any) => key.publicKeyJwk
            );

            if (!keyAgreementEntry || !keyAgreementEntry.publicKeyJwk) {
                console.warn(`No suitable publicKeyJwk found in keyAgreement for DID: ${did}. Skipping.`);
                continue;
            }

            console.log(`Found keyAgreement key for ${did}: ${keyAgreementEntry.id}`);
            recipientKeys.push(keyAgreementEntry.publicKeyJwk as JWK);
        }

        // Ensure we have recipients other than the bucket itself
        if (recipientKeys.length <= 1) {
            throw new Error("No valid reader DIDs could be resolved to public keys.");
        }

        // 3. Encrypt for multiple recipients
        const jweObject = await encryptJWEForMultipleRecipients(plaintextBytes, recipientKeys);

        // TODO: Complete this function by uploading JWE and submitting to pallet
        console.warn("shareBucketKey is incomplete: JWE is created but not uploaded or submitted to the chain.");
        return { jweObject }
    }

    /**
     * Retrieves and decrypts the bucket's secret key (SKB) from a key-sharing message.
     *
     * @param bucketId The bucket to get the key for.
     * @param readerPrivateKeyJwk The private key of the reader trying to access the SKB.
     * @returns The bucket's secret key (SKB) in JWK format.
     */
    public async retrieveBucketSecretKey(bucketId: number, readerPrivateKeyJwk: JWK): Promise<JWK> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        console.log(`Attempting to retrieve SKB for bucket ${bucketId} as a reader.`);

        // 1. Query the pallet for key-sharing messages in the bucket.
        const messageEntries = await this.polkadotApi.query.buckets.messages.entries(bucketId);
        const keySharingMessages = messageEntries
            .filter(([, value]) => (value as any).isSome) // Ensure the Option has a value
            .map(([key, value]) => {
                const unwrappedValue = (value as any).unwrap(); // Cast to 'any' to access unwrap()
                const messageData = unwrappedValue.toPrimitive(); // Use toPrimitive() for a plain JS object
                const messageId = (key.args[1] as any).toNumber(); // The message ID is the second key in the double map
                return { ...messageData, id: messageId };
            })
            .filter(msg => msg.tag === "didcomm/key-sharing-v1"); // Use a specific tag for key sharing

        if (keySharingMessages.length === 0) {
            throw new Error(`No key-sharing message found in bucket ${bucketId}.`);
        }

        const keyMessageInfo = keySharingMessages.sort((a, b) => b.id - a.id)[0];
        console.log(`Found key-sharing message at CID: ${keyMessageInfo.reference}`);

        // 2. Download the JWE from storage
        const jweBytes = await this.config.storageAdapter.download(keyMessageInfo.reference);
        const jweObject = JSON.parse(new TextDecoder().decode(jweBytes));

        // 3. Decrypt using the reader's private key
        const decryptedBytes = await decryptGeneralJWE(jweObject, readerPrivateKeyJwk);
        const decryptedMsg = JSON.parse(new TextDecoder().decode(decryptedBytes));

        console.log("Successfully decrypted key-sharing message:", decryptedMsg);

        // 4. Extract the key
        if (!decryptedMsg.body.keys || decryptedMsg.body.keys.length === 0) {
            throw new Error("Decrypted key-sharing message has no keys.");
        }
        const skb = decryptedMsg.body.keys[0]; // Assuming the first key is the SKB

        return skb;
    }

    // --- Roles and Permissions Management ---

    /**
     * Adds an Admin to a specific bucket.
     * Must be called by a Manager of the parent entity.
     * @param entityId The ID of the parent entity (namespace).
     * @param bucketId The ID of the bucket.
     * @param adminAddress The address of the account to be made an admin.
     * @returns The transaction hash.
     */
    public async addAdmin(entityId: number, bucketId: number, adminAddress: string): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        const extrinsic = this.polkadotApi.tx.buckets.addAdmin(entityId, bucketId, adminAddress);

        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.AdminAdded.is(event),
            (eventRecord) => {
                const [, eventBucketId, eventAdmin] = eventRecord.event.data;
                if ((eventBucketId as any).toNumber() === bucketId && eventAdmin.toString() === adminAddress) {
                    return { success: true };
                }
                return null;
            }
        );
        return txHash;
    }

    /**
     * Removes an Admin from a specific bucket.
     * Must be called by a Manager of the parent entity.
     * @param entityId The ID of the parent entity (namespace).
     * @param bucketId The ID of the bucket.
     * @param adminAddress The address of the admin to be removed.
     * @returns The transaction hash.
     */
    public async removeAdmin(entityId: number, bucketId: number, adminAddress: string): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        const extrinsic = this.polkadotApi.tx.buckets.removeAdmin(entityId, bucketId, adminAddress);
        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.AdminRemoved.is(event),
            (eventRecord) => {
                const [, eventBucketId, eventAdmin] = eventRecord.event.data;
                if ((eventBucketId as any).toNumber() === bucketId && eventAdmin.toString() === adminAddress) {
                    return { success: true };
                }
                return null;
            }
        );
        return txHash;
    }


    /**
     * Adds a Manager to a specific entity (namespace).
     * Must be called by an existing Manager of the entity.
     * @param entityId The ID of the entity (namespace).
     * @param managerAddress The address of the account to be made a manager.
     * @returns The transaction hash.
     */
    public async addManager(entityId: number, managerAddress: string): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        const extrinsic = this.polkadotApi.tx.buckets.addManager(entityId, managerAddress);
        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.ManagerAdded.is(event),
            (eventRecord) => {
                const [eventNamespaceId, eventManager] = eventRecord.event.data;
                if ((eventNamespaceId as any).toNumber() === entityId && eventManager.toString() === managerAddress) {
                    return { success: true };
                }
                return null;
            }
        );
        return txHash;
    }

    /**
     * Removes a Manager from a specific entity (namespace).
     * Must be called by an existing Manager of the entity.
     * @param entityId The ID of the entity (namespace).
     * @param managerAddress The address of the manager to be removed.
     * @returns The transaction hash.
     */
    public async removeManager(entityId: number, managerAddress: string): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        const extrinsic = this.polkadotApi.tx.buckets.removeManager(entityId, managerAddress);
        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.ManagerRemoved.is(event),
            (eventRecord) => {
                const [eventNamespaceId, eventManager] = eventRecord.event.data;
                if ((eventNamespaceId as any).toNumber() === entityId && eventManager.toString() === managerAddress) {
                    return { success: true };
                }
                return null;
            }
        );
        return txHash;
    }


    /**
     * Adds a Contributor to a specific bucket.
     * Must be called by an Admin of the bucket.
     * @param entityId The ID of the parent entity.
     * @param bucketId The ID of the bucket.
     * @param contributorAddress The address of the account to be made a contributor.
     * @returns The transaction hash.
     */
    public async addContributor(entityId: number, bucketId: number, contributorAddress: string): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        const extrinsic = this.polkadotApi.tx.buckets.addContributor(entityId, bucketId, contributorAddress);

        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.ContributorAdded.is(event),
            (eventRecord) => {
                const [, eventBucketId, eventContributor] = eventRecord.event.data;
                if ((eventBucketId as any).toNumber() === bucketId && eventContributor.toString() === contributorAddress) {
                    return { success: true };
                }
                return null;
            }
        );
        return txHash;
    }

    /**
     * Removes write access for a Contributor from a specific bucket.
     * Must be called by an Admin of the bucket.
     * @param entityId The ID of the parent entity.
     * @param bucketId The ID of the bucket.
     * @param contributorAddress The address of the contributor to remove.
     * @returns The transaction hash.
     */
    public async removeContributor(entityId: number, bucketId: number, contributorAddress: string): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        const extrinsic = this.polkadotApi.tx.buckets.removeContributor(entityId, bucketId, contributorAddress);
        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.ContributorRemoved.is(event),
            (eventRecord) => {
                const [, eventBucketId, eventContributor] = eventRecord.event.data;
                if ((eventBucketId as any).toNumber() === bucketId && eventContributor.toString() === contributorAddress) {
                    return { success: true };
                }
                return null;
            }
        );
        return txHash;
    }


    // --- Bucket and Tag Management ---

    /**
     * Pauses write operations on a bucket.
     * Must be called by an Admin of the bucket.
     * @param entityId The ID of the parent entity (namespace).
     * @param bucketId The ID of the bucket to pause.
     * @returns The transaction hash.
     */
    public async pauseBucketWrites(entityId: number, bucketId: number): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        const extrinsic = this.polkadotApi.tx.buckets.pauseWriting(entityId, bucketId);
        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.PausedBucket.is(event),
            (eventRecord) => {
                const [, eventBucketId] = eventRecord.event.data;
                if ((eventBucketId as any).toNumber() === bucketId) {
                    return { success: true };
                }
                return null;
            }
        );
        return txHash;
    }

    /**
     * Creates a new tag that can be used for messages within a bucket.
     * Must be called by an Admin of the bucket.
     * @param bucketId The ID of the bucket to add the tag to.
     * @param tag The string tag to create.
     * @returns The transaction hash.
     */
    public async createTag(bucketId: number, tag: string): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        const extrinsic = this.polkadotApi.tx.buckets.createTag(bucketId, tag);
        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.NewTag.is(event),
            (eventRecord) => {
                const [eventBucketId, eventTag] = eventRecord.event.data;
                if ((eventBucketId as any).toNumber() === bucketId && eventTag.toString() === tag) {
                    return { success: true };
                }
                return null;
            }
        );
        return txHash;
    }


    // --- Governance Functions ---

    /**
     * Removes an entire entity (namespace) and all of its associated buckets and messages.
     * Must be called by a governance origin.
     * @param entityId The ID of the entity (namespace) to remove.
     * @returns The transaction hash.
     */
    public async removeNamespace(entityId: number): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        const extrinsic = this.polkadotApi.tx.buckets.removeNamespace(entityId);
        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.NamespaceDeleted.is(event),
            (eventRecord) => {
                const [eventNamespaceId] = eventRecord.event.data;
                if ((eventNamespaceId as any).toNumber() === entityId) {
                    return { success: true };
                }
                return null;
            }
        );
        return txHash;
    }

    /**
     * Removes a specific bucket and its messages from an entity.
     * Must be called by a governance origin.
     * @param entityId The ID of the parent entity.
     * @param bucketId The ID of the bucket to remove.
     * @returns The transaction hash.
     */
    public async removeBucket(entityId: number, bucketId: number): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        const extrinsic = this.polkadotApi.tx.buckets.removeBucket(entityId, bucketId);
        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.BucketDeleted.is(event),
            (eventRecord) => {
                const [eventNamespaceId, eventBucketId] = eventRecord.event.data;
                if ((eventNamespaceId as any).toNumber() === entityId && (eventBucketId as any).toNumber() === bucketId) {
                    return { success: true };
                }
                return null;
            }
        );
        return txHash;
    }

    /**
     * Removes a specific message from a bucket.
     * Must be called by a governance origin.
     * @param bucketId The ID of the bucket containing the message.
     * @param messageId The ID of the message to remove.
     * @returns The transaction hash.
     */
    public async removeMessage(bucketId: number, messageId: number): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        const extrinsic = this.polkadotApi.tx.buckets.removeMessage(bucketId, messageId);
        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.MessageDeleted.is(event),
            (eventRecord) => {
                const [eventBucketId, eventMessageId] = eventRecord.event.data;
                if ((eventBucketId as any).toNumber() === bucketId && (eventMessageId as any).toNumber() === messageId) {
                    return { success: true };
                }
                return null;
            }
        );
        return txHash;
    }
}