export interface StorageAdapter {
    upload: (data: Uint8Array | string) => Promise<string>; // Returns CID/URL
    download: (identifier: string) => Promise<Uint8Array>;
}

export interface DidResolver {
    resolve: (did: string) => Promise<any>; // Simplified, use actual DID ResolutionResult type
}

export interface Signer {
    // Interface for signing Substrate extrinsics
    // This will depend on how you manage user keys (e.g., Polkadot.js extension, local keypair)
    // For now, it can be a placeholder
    signPayload: (payload: any) => Promise<{ signature: string }>; // Simplified
    getAddress: () => string; // The DID/address of the signer
}

export interface AssetDidCommClientConfig {
    storageAdapter: StorageAdapter;
    rpcEndpoint?: string; // For Substrate pallet (optional for initial mock)
    didResolver: DidResolver; // To fetch DIDs for keys
    signer: Signer; // To sign transactions
    // Potentially default KILT API endpoint if not covered by didResolver
}