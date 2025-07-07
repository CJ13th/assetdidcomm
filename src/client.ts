// src/client.ts
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
     * Sets or rotates the public key (PKB) for a bucket, making it writable.
     * Must be called by an Admin of the bucket.
     * @param entityId The ID of the parent entity.
     * @param bucketId The ID of the bucket.
     * @param publicKeyJwk The new public key in JWK format.
     * @returns The transaction hash.
     */
    public async setBucketPublicKey(entityId: number, bucketId: number, publicKeyJwk: JWK): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        const keyId = publicKeyJwk.kid || JSON.stringify(publicKeyJwk);
        const extrinsic = this.polkadotApi.tx.buckets.resumeWriting(entityId, bucketId, keyId);

        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.BucketWritableWithKey.is(event),
            (eventRecord) => {
                const [, eventBucketId, eventKey] = eventRecord.event.data;
                if ((eventBucketId as any).toNumber() === bucketId && eventKey.toString() === keyId) {
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
    private async fetchBucketPublicKey(entityId: number, bucketId: number): Promise<JWK | null> {
        console.warn(`Fetching PKB for entity ${entityId}, bucket ${bucketId} - MOCK IMPLEMENTATION`);
        // TODO: Implement actual pallet query
        // Example (pseudo-code for pallet query):
        // if (!this.polkadotApi) {
        //   console.error("Polkadot API not initialized. Cannot fetch PKB.");
        //   return null;
        // }
        // try {
        //   const bucketInfoRaw = await this.polkadotApi.query.bucket.buckets(entityId, bucketId);
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

    private async submitToPallet(
        entityId: number,
        bucketId: number,
        messageData: { reference: string; tag: string; metadata?: object }
    ): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        const messageInput = {
            reference: messageData.reference,
            tag: messageData.tag,
            metadata: messageData.metadata || {}
        };

        const extrinsic = this.polkadotApi.tx.buckets.write(entityId, bucketId, messageInput);

        // In a `write` operation, we might just care that it's finalized, 
        // but watching for the event is more robust.
        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.NewMessage.is(event),
            (eventRecord) => {
                // We could validate the message ID if we knew it beforehand,
                // but for now, just confirming the event for the correct bucket is enough.
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
        // The spec has latestKey/previousKeys, but the module has `keys`. We adapt.
        // The key being shared is the *secret key* of the bucket.
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

            // Find the first keyAgreement key that is a JWK.
            // A real implementation might be more selective.
            const keyAgreementEntry = didDocument.keyAgreement.find(
                (key) => key.publicKeyJwk
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

        return
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
        // This is a simplified query. A real implementation would need more robust filtering.
        const messageEntries = await this.polkadotApi.query.buckets.messages.entries(bucketId);
        const keySharingMessages = messageEntries
            .filter(([, value]) => (value as any).isSome) // Ensure the Option has a value
            .map(([key, value]) => {
                const unwrappedValue = (value as any).unwrap(); // Cast to 'any' to access unwrap()
                const messageData = unwrappedValue.toPrimitive(); // Use toPrimitive() for a plain JS object

                // The message ID is the second argument in the double map storage key
                const messageId = (key.args[1] as any).toNumber(); // Cast to 'any' to access toNumber()

                return { ...messageData, id: messageId };
            })
            .filter(msg => msg.tag === "didcomm/key-sharing-v1");

        if (keySharingMessages.length === 0) {
            throw new Error(`No key-sharing message found in bucket ${bucketId}.`);
        }

        // For simplicity, we take the latest one.
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

    /**
 * Sets an Admin for a specific bucket.
 * Must be called by a Manager of the parent entity.
 * @param entityId The ID of the parent entity.
 * @param bucketId The ID of the bucket.
 * @param adminDid The DID of the account to be made an admin.
 * @returns The transaction hash.
 */
    public async addAdmin(entityId: number, bucketId: number, adminDid: string): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        const extrinsic = this.polkadotApi.tx.buckets.addAdmin(entityId, bucketId, adminDid);

        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.AdminAdded.is(event),
            (eventRecord) => {
                const [, eventBucketId, eventAdmin] = eventRecord.event.data;
                if ((eventBucketId as any).toNumber() === bucketId && eventAdmin.toString() === adminDid) {
                    return { success: true }; // We just need confirmation
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
     * @param contributorDid The DID of the account to be made a contributor.
     * @returns The transaction hash.
     */
    public async addContributor(entityId: number, bucketId: number, contributorDid: string): Promise<string> {
        if (!this.polkadotApi) throw new Error("Polkadot API not initialized.");

        // Note: The pallet extrinsic is grantWriteAccess, but we listen for ContributorAdded event
        const extrinsic = this.polkadotApi.tx.buckets.grantWriteAccess(entityId, bucketId, contributorDid);

        const { txHash } = await this._submitAndWatch(
            extrinsic,
            (event) => this.polkadotApi!.events.buckets.ContributorAdded.is(event),
            (eventRecord) => {
                const [, eventBucketId, eventContributor] = eventRecord.event.data;
                if ((eventBucketId as any).toNumber() === bucketId && eventContributor.toString() === contributorDid) {
                    return { success: true };
                }
                return null;
            }
        );
        return txHash;
    }
}
