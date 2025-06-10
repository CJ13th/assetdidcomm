// src/signers/polkadot-extension.ts
import type { Signer, SignerPayloadRaw } from '../config';
import { web3Enable, web3FromAddress } from '@polkadot/extension-dapp';

export class PolkadotExtensionSigner implements Signer {
    private address: string;
    private appName: string;

    constructor(address: string, appName: string = 'AssetDIDComm-Client') {
        this.address = address;
        this.appName = appName;
    }

    public getAddress(): string {
        return this.address;
    }

    public async signRaw(raw: SignerPayloadRaw): Promise<{ signature: string }> {
        await web3Enable(this.appName);
        const injector = await web3FromAddress(this.address);

        if (!injector.signer.signRaw) {
            throw new Error('The selected wallet extension does not support signRaw.');
        }

        // The injector expects the address and data to match what it's signing
        const signature = await injector.signer.signRaw({
            address: this.address,
            data: '0x' + Buffer.from(this.address, 'utf-8').toString('hex'), // Crust requires signing the address itself
            type: 'bytes',
        });

        return { signature: signature.signature };
    }

    // You will implement this later when submitting extrinsics.
    // For now, it can be a placeholder.
    public async signPayload(payload: any): Promise<{ signature: string }> {
        // Implementation for signing extrinsics will go here
        throw new Error("signPayload not yet implemented for PolkadotExtensionSigner.");
    }
}