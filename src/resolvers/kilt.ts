// src/resolvers/kilt.ts

import * as Kilt from '@kiltprotocol/sdk-js';
import type { Did, ResolutionResult } from '@kiltprotocol/types';

let isKiltConnected = false;

/**
 * Initializes the connection to the Kilt blockchain.
 * This must be called before any resolver or on-chain operations.
 * @param endpoint The WebSocket endpoint of the Kilt node.
 */
export async function initializeKilt(endpoint: string = 'wss://peregrine.kilt.io/'): Promise<void> {
    if (isKiltConnected) {
        console.log("KILT SDK is already connected.");
        return;
    }
    await Kilt.connect(endpoint);
    isKiltConnected = true;
    console.log(`KILT SDK connected to ${endpoint}`);
}

/**
 * Disconnects from the Kilt blockchain.
 * Should be called when the application is shutting down.
 */
export async function disconnectKilt(): Promise<void> {
    if (isKiltConnected) {
        await Kilt.disconnect();
        isKiltConnected = false;
        console.log("KILT SDK disconnected.");
    }
}

/**
 * Resolves a Kilt DID to its DID Document.
 * This function implements the DidResolver interface for your client.
 * @param did The Kilt DID to resolve (e.g., 'did:kilt:4...').
 * @returns The resolution result containing the DID Document.
 * @throws Error if the SDK is not connected, or if resolution fails.
 */
export async function kiltDidResolver(did: Did): Promise<ResolutionResult> {
    if (!isKiltConnected) {
        throw new Error("KILT SDK not initialized. Call initializeKilt() first.");
    }

    console.log(`Resolving Kilt DID: ${did}`);
    const resolutionResult = await Kilt.DidResolver.resolve(did);

    // Robust error handling inspired by the official Kilt examples
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