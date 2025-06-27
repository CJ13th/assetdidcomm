// In src/resolvers/did-resolver.ts

// --- FIX: Use the namespace import ---
import * as Kilt from '@kiltprotocol/sdk-js';
import type { ResolutionResult, Did } from '@kiltprotocol/types';

let isKiltConnected = false;

export async function initializeDidResolver(endpoint: string): Promise<void> {
    if (isKiltConnected) return;
    // --- FIX: Use the method from the namespace ---
    await Kilt.connect(endpoint);
    isKiltConnected = true;
    console.log(`KILT SDK connected to ${endpoint}`);
}

export async function disconnectDidResolver(): Promise<void> {
    if (isKiltConnected) {
        // --- FIX: Use the method from the namespace ---
        await Kilt.disconnect();
        isKiltConnected = false;
        console.log("KILT SDK disconnected.");
    }
}

export async function kiltDidResolver(did: Did): Promise<ResolutionResult> {
    if (!isKiltConnected) {
        throw new Error("KILT SDK not initialized. Call initializeDidResolver() first.");
    }

    console.log(`Resolving DID: ${did}`);
    // --- FIX: Access the resolver object via the Kilt namespace ---
    const resolutionResult = await Kilt.DidResolver.resolve(did);

    if (resolutionResult?.didResolutionMetadata?.error) {
        throw new Error(`DID Resolution error for ${did}: ${resolutionResult.didResolutionMetadata.error}`);
    }
    if (resolutionResult?.didDocumentMetadata?.deactivated) {
        throw new Error(`DID ${did} is deactivated.`);
    }
    if (!resolutionResult?.didDocument) {
        throw new Error(`DID Document not found for ${did}.`);
    }

    console.log(`Successfully resolved DID: ${resolutionResult.didDocument.id}`);
    return resolutionResult;
}