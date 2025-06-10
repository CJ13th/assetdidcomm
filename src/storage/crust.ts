import { StorageAdapter, Signer } from '../config';

interface CrustAdapterOptions {
    uploadGateway?: string;
    pinningEndpoint?: string;
    publicGateway?: string;
}

export class CrustStorageAdapter implements StorageAdapter {
    private signer: Signer;
    private options: Required<CrustAdapterOptions>;

    constructor(signer: Signer, options?: CrustAdapterOptions) {
        if (!signer) {
            throw new Error("A Signer is required for CrustStorageAdapter.");
        }
        this.signer = signer;

        this.options = {
            uploadGateway: options?.uploadGateway ?? 'https://crustipfs.xyz/api/v0/add',
            pinningEndpoint: options?.pinningEndpoint ?? 'https://pin.crustcode.com/psa/pins',
            publicGateway: options?.publicGateway ?? 'https://crustipfs.io/ipfs',
        };
    }

    /**
     * Uploads raw data to a Crust IPFS gateway and pins it.
     * @param data The raw data (e.g., an encrypted JWE) to upload.
     * @returns The IPFS Content Identifier (CID) for the uploaded data.
     */
    public async upload(data: Uint8Array | string): Promise<string> {
        console.log("CrustAdapter: Starting upload and pin process...");

        let dataToUpload: Uint8Array;
        // --- ADD THIS LOGIC ---
        // Ensure we are working with a Uint8Array before creating the Blob.
        if (typeof data === 'string') {
            dataToUpload = new TextEncoder().encode(data);
        } else {
            dataToUpload = data;
        }

        const authHeader = await this._createAuthHeader();

        // 1. Upload data to the gateway
        const dataBlob = new Blob([dataToUpload]);
        const formData = new FormData();
        // The API expects a file with a name.
        formData.append('file', dataBlob, 'assetdidcomm-message.jwe');

        const uploadResponse = await fetch(this.options.uploadGateway, {
            method: 'POST',
            headers: { Authorization: `Basic ${authHeader}` },
            body: formData,
        });

        if (!uploadResponse.ok) {
            const errorText = await uploadResponse.text();
            throw new Error(`Crust upload failed with status ${uploadResponse.status}: ${errorText}`);
        }

        const uploadResult = await uploadResponse.json();
        const cid = uploadResult.Hash;
        if (!cid) {
            throw new Error("Crust upload response did not contain a 'Hash' (CID).");
        }
        console.log(`CrustAdapter: Successfully uploaded. CID: ${cid}`);

        // 2. Pin the CID to ensure it persists
        console.log(`CrustAdapter: Pinning CID ${cid}...`);
        await this._pinToCrust(cid, authHeader);
        console.log(`CrustAdapter: Pinning successful.`);

        return cid;
    }

    /**
     * Downloads raw data from a public Crust/IPFS gateway.
     * @param identifier The IPFS CID of the content to download.
     * @returns The raw data as a Uint8Array.
     */
    public async download(identifier: string): Promise<Uint8Array> {
        const downloadUrl = `${this.options.publicGateway}/${identifier}`;
        console.log(`CrustAdapter: Downloading from ${downloadUrl}`);
        const response = await fetch(downloadUrl);

        if (!response.ok) {
            throw new Error(`Failed to download from Crust gateway. Status: ${response.status}`);
        }

        const data = await response.arrayBuffer();
        return new Uint8Array(data);
    }

    /**
     * Creates the Base64-encoded authentication header required by Crust services.
     */
    private async _createAuthHeader(): Promise<string> {
        const address = this.signer.getAddress();
        const { signature } = await this.signer.signRaw({
            type: 'bytes',
            address,
            data: '0x' + Buffer.from(address, 'utf-8').toString('hex'), // Signing the address string itself
        });

        return Buffer.from(`sub-${address}:${signature}`).toString('base64');
    }

    /**
     * Pins a given CID using the Crust pinning service.
     */
    private async _pinToCrust(cid: string, authHeader: string): Promise<any> {
        const body = JSON.stringify({ cid, name: `assetdidcomm-${cid}` });

        const response = await fetch(this.options.pinningEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${authHeader}`, // Note: Pinning uses Bearer, upload uses Basic
            },
            body: body,
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Crust pinning failed with status ${response.status}: ${errorText}`);
        }

        return response.json();
    }
}