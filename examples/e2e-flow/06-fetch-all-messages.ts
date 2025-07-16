import { MediaItem } from 'message-module-js';
import { setup, readState, CONTRIBUTOR_PRIVATE_KEY_JWK } from './_setup';

/**
 * A helper function to process a decrypted DIDComm message and extract its content
 * in a user-friendly format, correctly parsing the two-part media-sharing structure.
 * @param msg The decrypted message object from retrieveBucketMessages.
 * @returns A string representing the displayable content of the message.
 */
function processMessageContent(msg: any): string {
    if (msg.type.includes('basicmessage')) {
        return `[Text] "${msg.body.content}"`;
    }

    if (msg.type.includes('media-sharing')) {
        console.log('MESSAGE FULL', JSON.stringify(msg, null, 2));
        // The 'attachments' array holds the data, the 'body.items' array holds the metadata.
        if (!msg.attachments || !msg.body?.items) {
            return '[Malformed Media-Sharing Message: Missing attachments or body.items]';
        }

        const processedAttachments = msg.body.items.map((item: any) => {
            // 1. Get the ID that links the body item to the full attachment.
            const attachmentId = item.attachment_id;
            if (!attachmentId) return '[Attachment metadata item is missing an attachment_id]';

            // 2. Find the full attachment data using this ID.
            const fullAttachment = msg.attachments.find((att: any) => att.id === attachmentId);
            if (!fullAttachment) return `[Attachment data not found for id: ${attachmentId}]`;

            const fileName = fullAttachment.fileName || 'untitled';

            // 3. Now, check inside the attachment's 'data' property for the content.
            if (fullAttachment.data?.base64) {
                try {
                    const decodedContent = Buffer.from(fullAttachment.data.base64, 'base64').toString('utf-8');
                    return `[Inlined Attachment: ${fileName}]\n      "${decodedContent}"`;
                } catch (e) {
                    return `[Inlined Attachment: Error decoding Base64 content]`;
                }
            } else if (fullAttachment.data?.links && fullAttachment.data.links.length > 0) {
                // This handles referenced media correctly.
                const link = fullAttachment.data.links[0];
                return `[Referenced Attachment: ${fileName}]\n      Link: ${link}\n      (Full decryption of referenced file would happen here)`;
            }

            return `[Unknown data format in attachment ID: ${attachmentId}]`;
        });

        return processedAttachments.join('\n\n      ');
    }

    return '[Unknown Message Type]';
}

async function main() {
    // We need clients for the Manager (Alice), Admin (Bob), and Contributor (Charlie)
    const { managerClient, adminClient, contributorClient, disconnectAll } = await setup();
    const state = readState();

    if (!state.namespaceId || state.bucketId === undefined) {
        throw new Error("State not found. Please run scripts 01-04 first.");
    }

    // For this test, Charlie will be the one fetching the feed at the end.
    const readerClient = contributorClient;

    try {
        // --- : Charlie retrieves and displays the entire feed ---
        const messageFeed = await readerClient.retrieveBucketMessages(state.bucketId, CONTRIBUTOR_PRIVATE_KEY_JWK);

        console.log("\n\n" + "=".repeat(80));
        console.log(`✅✅✅ BUCKET FEED SUCCESSFULLY RETRIEVED (${messageFeed.length} messages) ✅✅✅`);
        console.log("=".repeat(80));

        for (const msg of messageFeed) {
            console.log(`\n[Message #${msg.messageId}] from ${msg.from}---------------------`);

            if (msg.error) {
                console.log(`  Content: [Cannot be processed: ${msg.error}]`);
                continue;
            }

            if (msg.type.includes('basicmessage')) {
                console.log(`  Content: "${msg.body.content}"`);
            }
            else if (msg.type.includes('media-sharing') && msg.attachments) {
                for (const attachment of msg.attachments) {
                    // Check if our helper attached the decryptor function
                    if (typeof attachment.decryptFile === 'function') {
                        console.log(`  Attachment (Referenced): ${attachment.filename}`);
                        try {
                            // Call the on-demand decryptor!
                            const fileBytes = await attachment.decryptFile();
                            const fileContent = new TextDecoder().decode(fileBytes);
                            console.log("  ---------------- DECRYPTED CONTENT ----------------");
                            console.log(`  ${fileContent}`);
                            console.log("  -------------------------------------------------");
                        } catch (e: any) {
                            console.log(`  Could not decrypt file: ${e.message}`);
                        }
                    } else if (attachment.data?.base64) {
                        // Handle inlined files
                        const decodedContent = Buffer.from(attachment.data.base64, 'base64').toString('utf-8');
                        console.log(`  Attachment (Inlined): ${attachment.description}`);
                        console.log(`  Content: "${decodedContent}"`);
                    }
                }
            }
        }
        console.log("\n" + "=".repeat(80));


    } catch (error) {
        console.error("\n❌ Error in sending messages: send messages", error);
        process.exit(1);
    } finally {
        await disconnectAll();
    }
}

main().catch(console.error);