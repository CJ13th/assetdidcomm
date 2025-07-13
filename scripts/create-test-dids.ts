
import 'dotenv/config';
import * as Kilt from '@kiltprotocol/sdk-js'
import type {
    KiltKeyringPair,
    KiltEncryptionKeypair,
    DidDocument,
    KiltAddress,
    MultibaseKeyPair,
    SignerInterface,
} from '@kiltprotocol/types'

import { Crypto } from '@kiltprotocol/utils'

import { Multikey } from '@kiltprotocol/utils'

import {
    DidHelpers,
    DidResolver,
    disconnect,
    generateKeypair,
    init,
    connect,
} from '@kiltprotocol/sdk-js';
import { JWK } from 'jose';

function u8aToBase64Url(data: Uint8Array): string {
    return Buffer.from(data).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}


async function main() {
    const api = await connect('wss://peregrine.kilt.io');
    await init();

    console.log('✅ Successfully connected to the KILT blockchain.');

    // 1. Set up a funded account to pay for transactions.
    const submitter = Crypto.makeKeypairFromUri(process.env.KILT_FAUCET!);
    console.log(`🔑 Submitter Account: ${submitter.address}`);

    // 2. Generate keypairs for the new DID.
    // An authentication key is required to create the DID and control it later.
    const authenticationKey = generateKeypair();
    console.log(
        `🔑 Generated Authentication Key (Multibase Public): ${authenticationKey.publicKeyMultibase} (Multibase Secret): ${authenticationKey.secretKeyMultibase}`
    );

    // A key agreement (encryption) key is needed for encrypting and decrypting messages.
    const keyAgreementKey = Crypto.makeEncryptionKeypairFromSeed();
    console.log(
        `🔑 Generated Key Agreement Key (Public): ${Crypto.u8aToHex(
            keyAgreementKey.publicKey
        )} (Secret): ${Crypto.u8aToHex(
            keyAgreementKey.secretKey
        )}
        `
    );

    console.log("\n--- Converting to JSON Web Key (JWK) ---");
    const publicKeyBase64Url = u8aToBase64Url(keyAgreementKey.publicKey);
    const secretKeyBase64Url = u8aToBase64Url(keyAgreementKey.secretKey);

    const privateKeyJwk: JWK = {
        kty: 'OKP',          // Key Type for Edwards-curve keys is "Octet Key Pair"
        crv: 'X25519',       // The curve name matches the key type
        x: publicKeyBase64Url,  // The 'x' parameter is the Base64URL encoded public key
        d: secretKeyBase64Url,   // The 'd' parameter is the Base64URL encoded private key
    };

    console.log("\n✅ Conversion Successful!");
    console.log("Generated Private Key JWK (copy this entire object):");
    console.log(JSON.stringify(privateKeyJwk, null, 2));

    // 3. Create the DID on the blockchain.
    // This first transaction only includes the authentication key.
    console.log('\n🚀 Creating DID on chain...');
    const createDidResult = await DidHelpers.createDid({
        api,
        submitter,
        signers: [authenticationKey], // The authentication key signs its own addition.
        fromPublicKey: authenticationKey,
    }).submit({ awaitFinalized: false });

    console.log('createDidResult:', createDidResult);

    if (createDidResult.status !== 'confirmed') {
        throw new Error('Failed to create DID.');
    }
    let didDocument = createDidResult.asConfirmed.didDocument;
    console.log(`✅ DID ${didDocument.id} created successfully.`);



    // 4. Add the key agreement key to the DID.
    // This is a second transaction that updates the DID document on-chain.
    console.log('\n🚀 Adding Key Agreement key to the DID...');
    const addKeyAgreementResult = await DidHelpers.setVerificationMethod({
        api,
        didDocument,
        submitter,
        signers: [authenticationKey], // The authentication key must sign this update.
        publicKey: keyAgreementKey,
        relationship: 'keyAgreement',
    }).submit({ awaitFinalized: false });

    if (addKeyAgreementResult.status !== 'confirmed') {
        throw new Error('Failed to add key agreement key.');
    }
    didDocument = addKeyAgreementResult.asConfirmed.didDocument;
    console.log('✅ Key Agreement key added successfully.');

    // 5. Resolve the final DID document from the blockchain.
    console.log(`\n🧐 Resolving DID: ${didDocument.id}`);
    const resolvedDid = await DidResolver.resolve(didDocument.id);

    if (!resolvedDid?.didDocument) {
        throw new Error('Could not resolve the DID.');
    }
    console.log('✅ DID Resolved. Final Document:');
    console.log(JSON.stringify(resolvedDid.didDocument, null, 2));

    // Verify that the key agreement key is present in the resolved document.
    if (!resolvedDid.didDocument.keyAgreement) {
        throw new Error('The keyAgreement key was not found in the resolved DID.');
    }

    // 6. Demonstrate encryption and decryption.
    console.log('\n🔒 Demonstrating Encryption & Decryption...');

    // Create another party (the sender) to encrypt a message for our DID.
    const senderEncryptionKeys: KiltEncryptionKeypair =
        Crypto.makeEncryptionKeypairFromSeed();

    // The sender needs the receiver's public keyAgreement key.
    // We extract it from the resolved DID Document.
    const receiverKeyAgreementVm = resolvedDid.didDocument.verificationMethod?.find(
        (vm) => vm.id === resolvedDid.didDocument!.keyAgreement![0]
    );
    if (!receiverKeyAgreementVm) {
        throw new Error('Could not find receiver key agreement VM.');
    }
    const receiverPublicKey = Multikey.decodeMultibaseKeypair(
        receiverKeyAgreementVm
    ).publicKey;

    // The message to be encrypted.
    const message = 'Hello KILT! This is a secret message.';
    console.log(`\nOriginal message: "${message}"`);

    // Encrypt the message using the sender's secret key and the receiver's public key.
    const encryptedMessage = Crypto.encryptAsymmetricAsStr(
        message,
        receiverPublicKey,
        senderEncryptionKeys.secretKey
    );
    console.log(`Encrypted message (nonce:box): ${encryptedMessage.nonce}:${encryptedMessage.box}`);

    // Decrypt the message using the receiver's secret key (which we have) and the sender's public key.
    const decryptedMessage = Crypto.decryptAsymmetricAsStr(
        encryptedMessage,
        senderEncryptionKeys.publicKey,
        keyAgreementKey.secretKey
    );
    console.log(`Decrypted message: "${decryptedMessage}"`);

    // Check if the decrypted message matches the original.
    if (message !== decryptedMessage) {
        throw new Error('Decryption failed: messages do not match.');
    }
    console.log('\n✅ Encryption and decryption successful!');
}

main()
    .then(() => console.log('\nScript finished successfully.'))
    .catch((e) => {
        console.error(e);
        process.exit(1);
    })
    .finally(disconnect);