// src/resolvers/kilt.ts
import {
    init,
    connect,
    disconnect,
    DidResolver as KiltSDKResolver, // Alias the SDK's resolver to avoid name clashes
} from '@kiltprotocol/sdk-js';
import type { Did, ResolutionResult } from '@kiltprotocol/types';
import type { DidResolver as IDidResolver } from '../config';

/**
 * A resolver for KILT DIDs that connects to a KILT blockchain node.
 * It implements the DidResolver interface for use with the AssetDidCommClient.
 */
export class KiltDidResolver implements IDidResolver {
    private endpoint: string;
    private isConnected: boolean = false;

    /**
     * Creates an instance of KiltDidResolver.
     * @param endpoint The WebSocket endpoint of the Kilt node. Defaults to the Peregrine testnet.
     */
    constructor(endpoint: string = 'wss://peregrine.kilt.io/') {
        this.endpoint = endpoint;
    }

    /**
     * Initializes the connection to the Kilt blockchain using the explicit two-step process.
     */
    public async connect(): Promise<void> {
        if (this.isConnected) {
            console.log("KiltDidResolver is already connected.");
            return;
        }

        // NEW LOGIC: Use the explicit two-step connection pattern.
        try {
            console.log(`KiltDidResolver: Connecting to ${this.endpoint}...`);
            await connect(this.endpoint); // Step 1: Establish the WebSocket connection.

            console.log('KiltDidResolver: Initializing SDK services...');
            await init(); // Step 2: Initialize the rest of the SDK that depends on the connection.

            this.isConnected = true;
            console.log(`✅ KiltDidResolver connected and initialized successfully.`);
        } catch (e) {
            console.error("Failed to connect or initialize KiltDidResolver", e);
            throw e;
        }
    }

    /**
     * Disconnects from the Kilt blockchain.
     */
    public async disconnect(): Promise<void> {
        if (this.isConnected) {
            // CHANGE: Use the specific disconnect function from the SDK
            await disconnect();
            this.isConnected = false;
            console.log("KiltDidResolver disconnected.");
        }
    }

    /**
     * Resolves a Kilt DID to its DID Document.
     */
    public async resolve(did: Did | string): Promise<ResolutionResult> {
        if (!this.isConnected) {
            throw new Error("KiltDidResolver is not connected. Call connect() on the resolver instance first.");
        }

        console.log(`Resolving Kilt DID: ${did}`);
        // CHANGE: Use the aliased resolver for clarity
        const resolutionResult = await KiltSDKResolver.resolve(did as Did);

        // Robust error handling remains the same
        if (resolutionResult.didResolutionMetadata?.error) {
            throw new Error(`DID Resolution error for ${did}: ${resolutionResult.didResolutionMetadata.error}`);
        }
        if (resolutionResult.didDocumentMetadata?.deactivated) {
            throw new Error(`DID ${did} has been deactivated.`);
        }
        if (!resolutionResult.didDocument) {
            throw new Error(`DID Document not found for ${did}.`);
        }

        console.log(`Successfully resolved DID: ${resolutionResult.didDocument.id}`);
        return resolutionResult;
    }
}