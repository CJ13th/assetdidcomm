import { Did } from "@kiltprotocol/types";
import { DidResolver, Signer, SignerPayloadRaw } from "../config";

// Mock Signer (ensure it's correctly implementing the Signer interface)
export class MockSigner implements Signer {
    private address: string;
    constructor(address: string = "did:mock:signer") {
        this.address = address;
    }
    getAddress(): string {
        return this.address;
    }

    public async signRaw(raw: SignerPayloadRaw): Promise<{ signature: string }> {
        console.log(`MockSigner: Signing raw data for ${this.address}:`, raw.data);
        // In a real signer, this would produce a real cryptographic signature.
        // For a mock, we just return a predictable but unique-looking string.
        const mockSignature = `mock_raw_sig_for_${raw.address}_signing_${raw.data.substring(0, 10)}...`;
        return { signature: mockSignature };
    }

    public async signPayload(payload: any): Promise<{ signature: string }> {
        console.log(`MockSigner: Signing payload for ${this.address}:`, payload);
        return { signature: "mock_signature_" + Math.random().toString(36).substring(7) };
    }
}

// Mock DID Resolver (ensure it's correctly implementing the DidResolver interface)
export class MockDidResolver implements DidResolver {
    async resolve(did: string): Promise<any> {
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
