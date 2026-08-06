// ── ShelbyNet upload ─────────────────────────────────────────────────────
//
// Two-step real upload, both genuinely hitting ShelbyNet:
//
//  1. ON-CHAIN REGISTRATION (Aptos transaction, signed by the user's wallet)
//     We build the `register_blob` Move call payload ourselves (the same
//     payload the official SDK's ShelbyBlobClient.registerBlob() builds
//     internally) and submit it via the AIP-62 wallet standard. This means
//     Petra signs it — no private key ever touches our code.
//
//  2. RPC BYTE UPLOAD (multipart upload to the Shelby storage nodes)
//     This step is authenticated by API key only (no wallet signature
//     required by the protocol) and is handled directly by the SDK's
//     ShelbyRPCClient.putBlob().
//
// Together these two steps are what the official `ShelbyClient.upload()`
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

let _provider = null;
async function getProvider() {
  if (!_provider) _provider = await createDefaultErasureCodingProvider();
  return _provider;
}

/**
 * Build the register_blob Move payload — mirrors
 * ShelbyBlobClient.createRegisterBlobPayload() but standalone so we don't
 * need a full local-key Account.
 */

function buildRegisterBlobPayload({ blobName, expirationMicros, blobMerkleRoot, numChunksets, blobSize, encoding }) {
  return {
    function: `${SHELBY_DEPLOYER.toString()}::blob_metadata::register_blob`,
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

  // Wait for the transaction to be indexed by ShelbyNet before uploading bytes
await new Promise(r => setTimeout(r, 5000));

  onProgress?.('uploading-bytes');
  const rpc = new ShelbyRPCClient({
    network: 'shelbynet',
    apiKey: SHELBY_API_KEY,
    rpc: { baseUrl: SHELBYNET_RPC_BASE },
  });

  await rpc.putBlobChunksets({
    accountAddress: ownerAddress,
    blobName,
    blobData: data,
    commitments,
  });

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
