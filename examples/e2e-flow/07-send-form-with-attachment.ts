import { setup, readState } from './_setup';
import * as fs from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { createMediaItemMessage } from 'message-module-js';
import {
    encryptJWE,
    calculateSha256Digest
} from '../../src/crypto/encryption';
import type { MediaItemInlined, MediaItemReferenced } from 'message-module-js';

// Define the structure of our form's text data
interface ProjectUpdateFormData {
    project_name: string;
    update_message: string;
    status: 'on-track' | 'delayed' | 'completed';
}

async function main() {
    // The Admin/Contributor will send the message
    const { adminClient, disconnectAll } = await setup();
    const state = readState();

    if (!state.namespaceId || state.bucketId === undefined) {
        throw new Error("Namespace/Bucket ID not found in e2e-state.json. Please run previous scripts first.");
    }

    try {
        console.log(`\n--- [USER] Submitting a form with text and an attachment to Bucket ${state.bucketId} ---`);

        // === Step 1: Prepare All Form Content (Text and File) ===

        // 1a. The structured text data from the form fields
        const formData: ProjectUpdateFormData = {
            project_name: 'Decentralized Identifier Storage',
            update_message: 'Phase 2 implementation is complete. Moving to user acceptance testing.',
            status: 'on-track'
        };
        console.log("[1/8] Form text data prepared:", formData);

        // 1b. The file attachment
        // For this test, we'll create a dummy SVG file content.
        const svgContent = `<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg"><circle cx="50" cy="50" r="40" stroke="green" stroke-width="4" fill="yellow" /></svg>`;
        const fileBytes = new TextEncoder().encode(svgContent);
        const fileInfo = {
            content: fileBytes,
            mediaType: 'image/svg+xml',
            fileName: 'project-diagram.svg',
            description: 'Architectural diagram for Phase 2.'
        };
        console.log("[2/8] File attachment prepared.");


        // === Step 2: Package All Content into DIDComm Attachments ===

        // 2a. Package the text data as an INLINED attachment
        const formTextJson = JSON.stringify(formData);
        const formTextBase64 = Buffer.from(formTextJson).toString('base64');
        const formTextAttachment: MediaItemInlined = {
            id: 'form-data', // Use a semantic ID
            media_type: 'application/json',
            description: 'Project Update Form Data',
            base64: formTextBase64,
        };
        console.log("[3/8] Text data packaged as an inlined attachment.");

        // 2b. Encrypt and package the file as a REFERENCED attachment
        // This re-uses the two-layer encryption logic from `sendMediaMessage`
        const pkbJwk = await (adminClient as any).fetchBucketPublicKey(state.namespaceId, state.bucketId);
        if (!pkbJwk) throw new Error("Could not fetch bucket public key.");

        const mediaCEK = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedMediaBytes = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, mediaCEK, fileInfo.content);
        const mediaCid = await adminClient.config.storageAdapter.upload(new Uint8Array(encryptedMediaBytes));

        const rawMediaCekBytes = await crypto.subtle.exportKey('raw', mediaCEK);
        const encryptedMediaCekJwe = await encryptJWE(new Uint8Array(rawMediaCekBytes), pkbJwk);

        const fileHash = await calculateSha256Digest(fileInfo.content);
        const fileAttachment: MediaItemReferenced = {
            id: uuidv4(),
            media_type: fileInfo.mediaType,
            filename: fileInfo.fileName,
            description: fileInfo.description,
            link: `ipfs://${mediaCid}`,
            hash: `sha2-256:${fileHash}`,
            ciphering: {
                algorithm: 'AES-GCM-256+JWE', // A descriptive algorithm name
                parameters: {
                    iv: Buffer.from(iv).toString('hex'), // Send IV as hex
                    key: encryptedMediaCekJwe,
                }
            }
        };
        console.log("[4/8] File attachment packaged as a referenced attachment.");


        // === Step 3: Create, Encrypt, and Submit the Single "Container" Message ===

        // 3a. Create the single DIDComm message containing both items
        const didCommMessageString = createMediaItemMessage({
            id: uuidv4(),
            from: adminClient.config.signer.getAddress(),
            mediaItems: [formTextAttachment, fileAttachment] // Both items are in the same message!
        });
        console.log("[5/8] Final 'container' DIDComm message constructed.");

        // 3b. Encrypt the container message for the bucket
        const finalJweString = await encryptJWE(new TextEncoder().encode(didCommMessageString), pkbJwk);
        console.log("[6/8] Final message encrypted for the bucket.");

        // 3c. Upload the final JWE and submit to the pallet
        const outerJweCid = await adminClient.config.storageAdapter.upload(finalJweString);
        console.log(`[7/8] Final message uploaded to storage. CID: ${outerJweCid}`);

        const digestHex = await calculateSha256Digest(finalJweString);
        await (adminClient as any).submitToPallet(
            state.namespaceId,
            state.bucketId,
            {
                referenceObj: { reference: outerJweCid, digest: digestHex },
                tag: 'form-submission/project-update-v1', // Use a descriptive tag
                metadata: { unique: Math.floor(Math.random() * 1_000_000_000) }
            }
        );
        console.log("[8/8] Final message reference submitted to the pallet.");

        console.log("\n✅ Form with text and attachment submitted successfully in a single transaction!");

    } catch (error) {
        console.error("\n❌ Error in Step 7: Send Form With Attachment", error);
        process.exit(1);
    } finally {
        await disconnectAll();
    }
}

main().catch(console.error);