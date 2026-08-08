// ── ShelbyNet upload ─────────────────────────────────────────────────────
//
// Three-step real upload, all genuinely hitting ShelbyNet:
//
//  1. ON-CHAIN REGISTRATION (Aptos transaction, signed by the user's wallet)
//     We build the `register_blob` Move call payload ourselves (the same
//     payload the official SDK's ShelbyBlobClient.registerBlob() builds
//     internally) and submit it via the AIP-62 wallet standard. This means
//     Petra signs it — no private key ever touches our code.
//
//  2. RPC BYTE UPLOAD (chunkset upload to the Shelby storage providers)
//     Authenticated by API key, returns storage-provider acknowledgements
//     (spAcks) needed for step 3.
//
//  3. ON-CHAIN COMMIT (Aptos transaction, signed by the user's wallet)
//     Finalizes the pending blob under its object name using the spAcks
//     from step 2. Without this, the blob stays "pending" and 404s on
//     download — this step is what actually makes it retrievable.
//
// Together these three steps are what the official `ShelbyClient.upload()`
// helper does — we're just splitting it because the high-level helper
// expects a local-key `Account`, while we only have a browser wallet.

import {
  createDefaultErasureCodingProvider,
  generateCommitments,
  expectedTotalChunksets,
  defaultErasureCodingConfig,
  SHELBY_DEPLOYER,
  ShelbyRPCClient,
} from '@shelby-protocol/sdk/browser';
import { Hex } from '@aptos-labs/ts-sdk';
import { signAndSubmitTransaction } from './wallet.js';

const SHELBYNET_RPC_BASE = 'https://api.shelbynet.shelby.xyz/shelby';
const SHELBY_API_KEY = 'AG-LISDV5KTAQZGFQ2ZYUZX2RZHT2M1ONCUX';
const APTOS_FULLNODE = 'https://api.shelbynet.shelby.xyz/v1';

let _provider = null;
async function getProvider() {
  if (!_provider) _provider = await createDefaultErasureCodingProvider();
  return _provider;
}

/**
 * After a register_blob transaction confirms, read back the emitted
 * BlobRegisteredEvent to learn the blob's on-chain UID — required by
 * putBlobChunksets, and only available from this event (not from the
 * blob name itself, per the SDK's own docs).
 */
async function getBlobUidFromTx(txHash) {
  const eventType = `${SHELBY_DEPLOYER}::blob_metadata::BlobRegisteredEvent`;
  for (let attempt = 0; attempt < 10; attempt++) {
    const res = await fetch(`${APTOS_FULLNODE}/transactions/by_hash/${txHash}`);
    if (res.ok) {
      const tx = await res.json();
      const ev = (tx.events || []).find(e => e.type === eventType);
      if (ev) return ev.data.uid;
    }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error('Could not find BlobRegisteredEvent for transaction ' + txHash);
}

/** Wait for a submitted transaction to actually confirm on-chain. */
async function waitForTxSuccess(txHash) {
  for (let attempt = 0; attempt < 15; attempt++) {
    const res = await fetch(`${APTOS_FULLNODE}/transactions/by_hash/${txHash}`);
    if (res.ok) {
      const tx = await res.json();
      if (tx.type !== 'pending_transaction') {
        if (!tx.success) throw new Error(`Transaction failed: ${tx.vm_status}`);
        return tx;
      }
    }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error('Timed out waiting for transaction ' + txHash);
}

/**
 * Sort storage-provider acks by slot and pack them into the
 * (ack_bits, signatures) pair commit_object expects — the contract walks
 * the set bits low-to-high and consumes signatures in that same order.
 */
function encodeAcks(storageProviderAcks) {
  const sorted = [...storageProviderAcks].sort((a, b) => a.slot - b.slot);
  const ackBits = sorted.reduce((acc, ack) => acc | (1 << ack.slot), 0);
  const signatures = sorted.map(ack => Array.from(ack.signature));
  return { ackBits, signatures };
}

/**
 * Payload for commit_object — binds the written pending blob under its
 * object name, finalizing the upload. Without this, the blob stays
 * "pending" and is not retrievable via getBlob (404).
 */
function buildCommitObjectPayload({ uid, blobName, overwrite, storageProviderAcks }) {
  const { ackBits, signatures } = encodeAcks(storageProviderAcks);
  return {
    function: `${SHELBY_DEPLOYER}::blob_metadata::commit_object`,
    functionArguments: [
      uid,
      blobName,
      overwrite,
      null, // if_match_etag: Option<vector<u8>> => None
      ackBits,
      signatures,
    ],
  };
}

/**
 * Build the register_blob Move payload — mirrors
 * ShelbyBlobClient.createRegisterBlobPayload() but standalone so we don't
 * need a full local-key Account.
 */
function buildRegisterBlobPayload({ blobName, expirationMicros, blobMerkleRoot, numChunksets, blobSize, encoding }) {
  return {
    function: `${SHELBY_DEPLOYER}::blob_metadata::register_blob`,
    functionArguments: [
      blobName,
      'shelbynet-1',   // selectedLocation — the region identifier for ShelbyNet
      'shelbynet-1',   // locationHint — same, for consistency
      expirationMicros,
      Array.from(Hex.fromHexString(blobMerkleRoot).toUint8Array()),
      numChunksets,
      blobSize,
      0,               // payment tier
      encoding,        // erasure encoding scheme
      0,               // encryption enum: 0 = Unencrypted (we already AES-encrypt client-side)
    ],
  };
}

/**
 * Upload encrypted capsule bytes to ShelbyNet.
 *
 * @param wallet - AIP-62 wallet object (already connected)
 * @param ownerAddress - the connected wallet's address string
 * @param blobName - path/name for the blob on ShelbyNet, e.g. "capsules/abc123.bin"
 * @param data - Uint8Array of the data to store (the encrypted capsule payload)
 * @param expirationMicros - when ShelbyNet should be allowed to garbage-collect this blob
 * @param onProgress - optional callback(stepName) for UI updates
 *
 * @returns { txHash, blobName, merkleRoot }
 */
export async function uploadCapsuleToShelby({ wallet, ownerAddress, blobName, data, expirationMicros, onProgress }) {
  onProgress?.('generating-commitments');
  const provider = await getProvider();
  const commitments = await generateCommitments(provider, data);

  const cfg = defaultErasureCodingConfig();
  const chunksetSize = cfg.chunkSizeBytes * cfg.erasure_k;
  const numChunksets = expectedTotalChunksets(data.length, chunksetSize);

  onProgress?.('registering-onchain');
  const payload = buildRegisterBlobPayload({
    blobName,
    expirationMicros,
    blobMerkleRoot: commitments.blob_merkle_root,
    numChunksets,
    blobSize: data.length,
    encoding: cfg.enumIndex,
  });

  const txHash = await signAndSubmitTransaction(wallet, payload.function, payload.functionArguments);

  onProgress?.('uploading-bytes');
  const blobUid = await getBlobUidFromTx(txHash);

  const rpc = new ShelbyRPCClient({
    network: 'shelbynet',
    apiKey: SHELBY_API_KEY,
    rpc: { baseUrl: SHELBYNET_RPC_BASE },
  });

  const uploadResult = await rpc.putBlobChunksets({
    accountAddress: ownerAddress,
    uid: blobUid,
    blobName,
    blobData: data,
    commitments,
  });

  onProgress?.('finalizing-commit');
  const commitPayload = buildCommitObjectPayload({
    uid: blobUid,
    blobName,
    overwrite: true,
    storageProviderAcks: uploadResult.spAcks,
  });
  const commitTxHash = await signAndSubmitTransaction(wallet, commitPayload.function, commitPayload.functionArguments);
  await waitForTxSuccess(commitTxHash);

  onProgress?.('done');
  return { txHash, blobName, merkleRoot: commitments.blob_merkle_root };
}

export async function downloadCapsuleFromShelby({ ownerAddress, blobName }) {
  const rpc = new ShelbyRPCClient({
    network: 'shelbynet',
    apiKey: SHELBY_API_KEY,
    rpc: { baseUrl: SHELBYNET_RPC_BASE },
  });

  const blob = await rpc.getBlob({
    account: ownerAddress,
    blobName,
  });

  if (blob instanceof Uint8Array) return blob;
  if (typeof blob === 'string') return new TextEncoder().encode(blob);
  if (blob?.data instanceof Uint8Array) return blob.data;
  if (typeof blob?.data === 'string') return new TextEncoder().encode(blob.data);

  if (blob?.readable) {
    const chunks = [];
    const reader = blob.readable.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) chunks.push(value);
    }
    const total = chunks.reduce((n, c) => n + c.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) { out.set(c, offset); offset += c.length; }
    return out;
  }

  throw new Error('Unknown blob format: ' + JSON.stringify(Object.keys(blob || {})));
}
