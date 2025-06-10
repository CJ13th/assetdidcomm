import { StorageAdapter } from '../config';

interface PinataAdapterOptions {
    jwt: string;
    publicGateway?: string;
}

/**
 * An adapter for uploading and pinning data to the IPFS network via the Pinata service.
 * It uses a JWT for authentication, which is the recommended method by Pinata.
 */
export class PinataStorageAdapter implements StorageAdapter {
    private options: Required<PinataAdapterOptions>;
    private pinataApiUrl = 'https://api.pinata.cloud/pinning/pinFileToIPFS';

    constructor(options: PinataAdapterOptions) {
        if (!options.jwt) {
            throw new Error("A Pinata JWT is required for the PinataStorageAdapter.");
        }
        this.options = {
            jwt: options.jwt,
            // Uses Pinata's dedicated public gateway for fast retrieval
            publicGateway: options.publicGateway ?? 'https://gateway.pinata.cloud/ipfs',
        };
    }

    /**
     * Uploads and pins raw data using the Pinata API.
     * @param data The raw data to upload, as either a Uint8Array or a string.
     * @returns The IPFS Content Identifier (CID) for the uploaded data.
     */
    public async upload(data: Uint8Array | string): Promise<string> {
        // Ensure the data is a Blob, which is what FormData expects for files.
        const dataBlob = data instanceof Uint8Array
            ? new Blob([data])
            : new Blob([data], { type: 'text/plain' });

        const formData = new FormData();
        // The 'file' field is required by the Pinata API.
        formData.append('file', dataBlob, 'assetdidcomm-message.jwe');

        // Optional: Add metadata for easier management in the Pinata dashboard
        const metadata = JSON.stringify({ name: `AssetDIDComm Message - ${new Date().toISOString()}` });
        formData.append('pinataMetadata', metadata);

        console.log("PinataAdapter: Uploading and pinning file...");

        const response = await fetch(this.pinataApiUrl, {
            method: 'POST',
            headers: {
                // Pinata API uses Bearer token authentication with a JWT.
                Authorization: `Bearer ${this.options.jwt}`,
            },
            body: formData,
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Pinata upload failed with status ${response.status}: ${errorText}`);
        }

        const result = await response.json();
        if (!result.IpfsHash) {
            throw new Error("Pinata response did not contain an 'IpfsHash' (CID).");
        }

        console.log(`PinataAdapter: Successfully uploaded and pinned. CID: ${result.IpfsHash}`);
        return result.IpfsHash;
    }

    /**
     * Downloads raw data from the Pinata public gateway.
     * @param identifier The IPFS CID of the content to download.
     * @returns The raw data as a Uint8Array.
     */
    public async download(identifier: string): Promise<Uint8Array> {
        const downloadUrl = `${this.options.publicGateway}/${identifier}`;
        console.log(`PinataAdapter: Downloading from ${downloadUrl}`);

        const response = await fetch(downloadUrl);

        if (!response.ok) {
            throw new Error(`Failed to download from Pinata gateway. Status: ${response.status}`);
        }

        const data = await response.arrayBuffer();
        return new Uint8Array(data);
    }
}