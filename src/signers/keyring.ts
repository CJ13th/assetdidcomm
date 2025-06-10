import type { Signer, SignerPayloadRaw } from '../config';
import { Keyring } from '@polkadot/keyring';
import type { KeyringPair } from '@polkadot/keyring/types';
import { stringToHex, hexToU8a } from '@polkadot/util';

export class KeyringSigner implements Signer {
    private pair: KeyringPair;

    /**
     * Creates a signer from a secret seed phrase or URI.
     * WARNING: This is for backend/CLI use only. Do not expose seeds in a browser environment.
     * @param seed The secret seed (e.g., '//Alice', '0x123...', 'your twelve words ...').
     * @param type The cryptographic type for the keypair, defaults to 'sr25519'.
     */
    constructor(seed: string, type: 'sr25519' | 'ed25519' = 'sr25519') {
        const keyring = new Keyring({ type });
        this.pair = keyring.addFromUri(seed);
        console.log(`KeyringSigner initialized for address: ${this.pair.address}`);
    }

    public getAddress(): string {
        return this.pair.address;
    }

    /**
     * Signs a raw byte payload.
     * This is used for authentication with services like Crust.
     */
    public async signRaw(raw: SignerPayloadRaw): Promise<{ signature: string }> {
        // The Polkadot.js keyring's sign method expects a Uint8Array.
        // The raw.data is a hex string, so we need to convert it.
        const dataU8a = hexToU8a(raw.data);
        const signatureU8a = this.pair.sign(dataU8a);
        const signatureHex = '0x' + Buffer.from(signatureU8a).toString('hex');

        return { signature: signatureHex };
    }

    /**
     * Signs a Substrate extrinsic payload.
     * This implementation will need to be completed when you integrate with the pallet.
     */
    public async signPayload(payload: any): Promise<{ signature: string }> {
        // The real implementation would use this.pair.sign(payload)
        // after the polkadot/api constructs the payload.
        // For now, this placeholder is fine.
        console.warn("signPayload on KeyringSigner is a placeholder.");
        return { signature: "mock_extrinsic_signature_from_keyring" };
    }

    /**
     * Exposes the underlying keypair for direct use with Polkadot.js API's signAndSend method.
     */
    public getKeypair(): KeyringPair {
        return this.pair;
    }
}