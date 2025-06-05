// src/adapters/mock.ts
import { StorageAdapter, DidResolver, Signer } from '../config'; // Make sure Signer is imported if defined in config.ts

// Mock Storage Adapter (e.g., in-memory or local storage for testing)
export class MockStorageAdapter implements StorageAdapter {
    private store: Map<string, Uint8Array> = new Map();

    async upload(data: Uint8Array | string): Promise<string> { // <-- MODIFIED to accept string | Uint8Array
        const id = `mock-cid-${Math.random().toString(36).substring(7)}`;
        let dataToStore: Uint8Array;

        if (typeof data === 'string') {
            dataToStore = new TextEncoder().encode(data);
        } else {
            dataToStore = data;
        }

        this.store.set(id, dataToStore);
        console.log(`MockStorage: Uploaded ${dataToStore.length} bytes with id ${id}`);
        return id;
    }

    async download(identifier: string): Promise<Uint8Array> {
        const data = this.store.get(identifier);
        if (!data) throw new Error(`MockStorage: Data not found for identifier ${identifier}`);
        console.log(`MockStorage: Downloaded ${data.length} bytes for id ${identifier}`);
        return data;
    }
}

// Mock DID Resolver (ensure it's correctly implementing the DidResolver interface)
export class MockDidResolver implements DidResolver {
    async resolve(did: string): Promise<any> { // Consider using a specific DID Document type
        console.log(`MockDidResolver: Resolving ${did}`);
        if (did === "did:example:test1" || did === "did:example:test2" || did === "did:mock:signer") {
            return {
                didDocument: {
                    id: did,
                    verificationMethod: [{
                        id: `${did}#key-1`,
                        type: "JsonWebKey2020",
                        controller: did,
                        publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "mockPublicKeyEd" }
                    }],
                    keyAgreement: [{
                        id: `${did}#key-agreement-1`,
                        type: "X25519KeyAgreementKey2019",
                        controller: did,
                        publicKeyJwk: { kty: "OKP", crv: "X25519", x: "mockKeyAgreementKeyX25519" }
                    }]
                }
            };
        }
        throw new Error(`MockDidResolver: DID ${did} not found`);
    }
}

// Mock Signer (ensure it's correctly implementing the Signer interface)
export class MockSigner implements Signer {
    private address: string;
    constructor(address: string = "did:mock:signer") {
        this.address = address;
    }
    getAddress(): string {
        return this.address;
    }
    async signPayload(payload: any): Promise<{ signature: string }> { // Make sure payload type matches Signer interface
        console.log(`MockSigner: Signing payload for ${this.address}:`, payload);
        return { signature: "mock_signature_" + Math.random().toString(36).substring(7) };
    }
}