// ── Shelby Time Capsule contract bridge ──────────────────────────────────
//
// Talks to our own `shelby_capsule::time_capsule` Move module deployed on
// ShelbyNet. See /move/sources/shelby_time_capsule.move for the contract.
//
// IMPORTANT: CONTRACT_ADDRESS below must be set to the address the module
// was published to (see /move/DEPLOY.md for publish instructions). Until
// then this module cannot function — there is no fallback, because a
// fallback would silently defeat the entire point of on-chain enforcement.

import { signAndSubmitTransaction } from './wallet.js';

export const CONTRACT_ADDRESS = '0x29a422b169a3dcb3ddecd073c77ee50407a3dc7aa8396edb0198b7599668f18d';
const APTOS_FULLNODE = 'https://api.shelbynet.shelby.xyz/v1';
const MODULE = 'time_capsule';

function fn(name) {
  return `${CONTRACT_ADDRESS}::${MODULE}::${name}`;
}

function assertDeployed() {
  if (CONTRACT_ADDRESS === '__SET_AFTER_PUBLISH__') {
    throw new Error(
      'Time capsule contract address is not configured. Publish the Move module first ' +
      '(see move/DEPLOY.md) and set CONTRACT_ADDRESS in src/lib/contract.js.'
    );
  }
}

/**
 * Seal a capsule on-chain: stores time_key, unlock_time, recipient, and the
 * ShelbyNet blob reference. The time_key is only released by the contract
 * once Aptos's on-chain clock passes unlock_time.
 */
export async function sealCapsuleOnChain(wallet, {
  timeKeyBytes,
  unlockTimeSeconds,
  recipientAddress, // '0x0' for public
  blobId,
  blobName,
  recipientBound,
}) {
  assertDeployed();
  const functionArguments = [
    Array.from(timeKeyBytes),
    unlockTimeSeconds.toString(),
    recipientAddress,
    Array.from(new TextEncoder().encode(blobId)),
    Array.from(new TextEncoder().encode(blobName)),
    recipientBound,
    CONTRACT_ADDRESS,
  ];
  const txHash = await signAndSubmitTransaction(wallet, fn('seal_capsule'), functionArguments);
  return txHash;
}

/**
 * Call a #[view] function on the Move contract via the Aptos REST API.
 * View calls are free, public reads — no wallet or gas needed.
 */
async function callView(functionId, typeArguments, functionArguments) {
  const res = await fetch(`${APTOS_FULLNODE}/view`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ function: functionId, type_arguments: typeArguments, arguments: functionArguments }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`View call failed (${res.status}): ${body}`);
  }
  return res.json();
}

/**
 * Get a capsule's public metadata. Safe to call any time, before or after
 * unlock — does not reveal the time_key.
 */
export async function getCapsuleInfo(capsuleId) {
  assertDeployed();
  const [unlockTime, author, recipient, blobIdHex, blobNameHex, createdAt, recipientBound] =
    await callView(fn('get_capsule_info'), [], [CONTRACT_ADDRESS, capsuleId.toString()]);

  return {
    unlockTime: Number(unlockTime),
    author,
    recipient,
    blobId: hexToUtf8(blobIdHex),
    blobName: hexToUtf8(blobNameHex),
    createdAt: Number(createdAt),
    recipientBound,
  };
}

function hexToUtf8(hex) {
  const clean = (hex || '').replace(/^0x/, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return new TextDecoder().decode(bytes);
}

/**
 * Check whether a capsule's unlock_time has passed, per the chain's clock.
 */
export async function isCapsuleUnlocked(capsuleId) {
  assertDeployed();
  const [unlocked] = await callView(fn('is_unlocked'), [], [CONTRACT_ADDRESS, capsuleId.toString()]);
  return !!unlocked;
}

function hexToBytes(hex) {
  const clean = String(hex).replace(/^0x/, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

/**
 * THE CORE ENFORCEMENT CALL.
 *
 * Attempts to retrieve the time_key for a capsule. The Move contract's
 * `get_time_key` view function asserts `now_seconds() >= unlock_time` on
 * the Aptos blockchain side — if the time hasn't come, this call fails
 * with an on-chain abort (E_NOT_YET_TIME), not a client-side check we
 * could bypass by editing JavaScript.
 *
 * @returns Uint8Array time_key bytes if unlocked
 * @throws if it's not yet time, or the capsule doesn't exist
 */
export async function getTimeKey(capsuleId) {
  assertDeployed();
  try {
    const [timeKeyRaw] = await callView(fn('get_time_key'), [], [CONTRACT_ADDRESS, capsuleId.toString()]);
    // Aptos view calls return vector<u8> as a hex string, not a number array
    return typeof timeKeyRaw === 'string' ? hexToBytes(timeKeyRaw) : new Uint8Array(timeKeyRaw);
  } catch (err) {
    const msg = String(err.message || err);
    if (msg.includes('E_NOT_YET_TIME') || msg.includes('"1"') || /\b1\b.*abort/.test(msg)) {
      throw new Error('NOT_YET_TIME');
    }
    throw err;
  }
}

/**
 * After a seal_capsule transaction confirms, read back the emitted
 * CapsuleSealed event to learn the assigned capsule_id (it's a counter
 * incremented on-chain, so we can't predict it client-side safely).
 */
export async function getCapsuleIdFromTx(txHash) {
  // Poll briefly — the fullnode may take a moment to index the transaction.
  for (let attempt = 0; attempt < 10; attempt++) {
    const res = await fetch(`${APTOS_FULLNODE}/transactions/by_hash/${txHash}`);
    if (res.ok) {
      const tx = await res.json();
      const ev = (tx.events || []).find(e => e.type?.endsWith('::time_capsule::CapsuleSealed'));
      if (ev) return Number(ev.data.capsule_id);
    }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error('Could not find CapsuleSealed event for transaction ' + txHash);
}

/** Get the total number of capsules ever sealed (informational only). */
export async function getCapsuleCount() {
  assertDeployed();
  const [count] = await callView(fn('get_capsule_count'), [], [CONTRACT_ADDRESS]);
  return Number(count);
}
/**
 * Register (or update) the caller's own X25519 encryption public key
 * on-chain, via signAndSubmitTransaction. This is the one-time setup step
 * a recipient does — independently, whenever they want, no sender needed.
 *
 * @param publicKeyBytes — 32-byte X25519 public key (from deriveX25519Keypair).
 */
export async function registerPubkey(wallet, publicKeyBytes) {
  assertDeployed();
  const txHash = await signAndSubmitTransaction(
    wallet,
    fn('register_pubkey'),
    [Array.from(publicKeyBytes), CONTRACT_ADDRESS]
  );
  return txHash;
}

/**
 * Look up a wallet's registered public key.
 * @returns Uint8Array (32 bytes) if found, or null if that address hasn't
 *          registered one yet (instead of throwing — callers usually want
 *          to check this before deciding whether to allow recipient-bound sealing).
 */
export async function getPubkey(userAddress) {
  assertDeployed();
  try {
    const [pubkeyRaw] = await callView(fn('get_pubkey'), [], [CONTRACT_ADDRESS, userAddress]);
    return typeof pubkeyRaw === 'string' ? hexToBytesLocal(pubkeyRaw) : new Uint8Array(pubkeyRaw);
  } catch (err) {
    const msg = String(err.message || err);
    if (msg.includes('E_PUBKEY_NOT_FOUND') || /\b6\b.*abort/.test(msg)) {
      return null;
    }
    throw err;
  }
}

/** Quick check: has this wallet registered a public key yet? */
export async function hasPubkey(userAddress) {
  assertDeployed();
  const [result] = await callView(fn('has_pubkey'), [], [CONTRACT_ADDRESS, userAddress]);
  return !!result;
}

function hexToBytesLocal(hex) {
  const clean = String(hex).replace(/^0x/, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}