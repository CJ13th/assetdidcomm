// src/adapters/mock.ts
import { StorageAdapter, DidResolver, Signer } from '../config'; // Make sure Signer is imported if defined in config.ts

// Mock Storage Adapter (e.g., in-memory or local storage for testing)
export class MockStorageAdapter implements StorageAdapter {
    private store: Map<string, Uint8Array> = new Map();

    async upload(data: Uint8Array | string): Promise<string> {
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


