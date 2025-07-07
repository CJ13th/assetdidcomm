// src/resolvers/kilt.ts

import * as Kilt from '@kiltprotocol/sdk-js';
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
     * Initializes the connection to the Kilt blockchain via the SDK.
     * This must be called before using the resolve method. In a client application,
     * this could be called alongside the main client's connect() method.
     */
    public async connect(): Promise<void> {
        if (this.isConnected) {
            console.log("KiltDidResolver is already connected.");
            return;
        }
        // The Kilt SDK v1.0.0+ uses a single init() function which handles the connection.
        await Kilt.init({ address: this.endpoint });
        this.isConnected = true;
        console.log(`KiltDidResolver connected to ${this.endpoint}`);
    }

    /**
     * Disconnects from the Kilt blockchain.
     * Should be called when the application is shutting down.
     */
    public async disconnect(): Promise<void> {
        if (this.isConnected) {
            await Kilt.disconnect();
            this.isConnected = false;
            console.log("KiltDidResolver disconnected.");
        }
    }

    /**
     * Resolves a Kilt DID to its DID Document.
     * This function implements the DidResolver interface for your client.
     * @param did The Kilt DID to resolve (e.g., 'did:kilt:4...').
     * @returns The resolution result containing the DID Document and metadata.
     * @throws Error if the SDK is not connected, or if resolution fails.
     */
    public async resolve(did: Did | string): Promise<ResolutionResult> {
        if (!this.isConnected) {
            // For robustness, applications should manage the connection state.
            // For example, by calling connect() on the resolver when the main client connects.
            throw new Error("KiltDidResolver is not connected. Call connect() on the resolver instance first.");
        }

        console.log(`Resolving Kilt DID: ${did}`);
        // The Kilt SDK's resolve function expects a `Did` type, which is a branded string.
        // Casting the input `string` to `Did` is safe and necessary here.
        const resolutionResult = await Kilt.DidResolver.resolve(did as Did);

        // Robust error handling, similar to the pattern in your create-test-dids.ts script.
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