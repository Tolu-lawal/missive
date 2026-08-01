import { waitForWallet, connectWallet, disconnectWallet, switchToShelbyNet, getCurrentNetwork } from './lib/wallet.js';
import { generateTimeKey, encryptMessage, boxToRecipient, bytesToHex } from './lib/crypto.js';
import { uploadCapsuleToShelby } from './lib/shelby.js';
import { sealCapsuleOnChain, getCapsuleIdFromTx, getPubkey, CONTRACT_ADDRESS } from './lib/contract.js';

const $ = (id) => document.getElementById(id);

let authorWallet = null;
let authorAddress = null;
let recipientAddress = null;   // set only once a valid registered key is found
let recipientPublicKey = null; // Uint8Array (32 bytes) or null
let capsuleSeed = null; // random hex, generated once, embedded in the blob name

function ensureCapsuleSeed() {
  if (!capsuleSeed) {
    capsuleSeed = bytesToHex(crypto.getRandomValues(new Uint8Array(16))).slice(2);
  }
  return capsuleSeed;
}

function showError(msg) { $('errorMsg').textContent = msg; $('errorMsg').classList.add('active'); }
function clearError() { $('errorMsg').classList.remove('active'); }

function setStep(id, state) {
  const el = $(id);
  el.className = 'progress-step ' + state;
  const icon = el.querySelector('.step-icon');
  if (state === 'active-step') icon.innerHTML = '<span class="spinner"></span>';
  else if (state === 'done') icon.textContent = '✓';
  else icon.textContent = '○';
}

// ── Contract deployment guard ──
if (CONTRACT_ADDRESS === '__SET_AFTER_PUBLISH__') {
  showError('The time capsule contract has not been deployed yet. See move/DEPLOY.md, publish the module, then set CONTRACT_ADDRESS in src/lib/contract.js.');
}

// ── Author wallet connect ──
$('walletBtn').addEventListener('click', async () => {
  if (authorWallet) return;
  const right = $('walletBtnRight');
  right.textContent = 'Detecting...';

  const wallet = await waitForWallet(3000);
  if (!wallet) {
    right.textContent = 'CONNECT →';
    window.open('https://petra.app/', '_blank');
    showError('Petra wallet not detected. Enable it for this site, refresh, and try again.');
    return;
  }

  try {
    authorAddress = await connectWallet(wallet);
    await switchToShelbyNet(wallet); // best-effort; Petra's changeNetwork is unreliable, don't trust its result
    const net = await getCurrentNetwork(wallet);
    const onShelbyNet = net && (
      String(net.chainId) === '114' ||
      String(net.chainId) === '0x72' ||
      String(net.name || '').toLowerCase() === 'shelbynet' ||
      String(net.url || '').includes('shelbynet.shelby.xyz')
    );
    authorWallet = wallet;

    if (!onShelbyNet) {
      showError('Petra is not on ShelbyNet (currently: ' + (net?.name || net?.chainId || 'unknown') + '). Please open Petra and manually switch the network to "Shelbynet" before sealing, then reconnect.');
    }

    $('walletDot').classList.add('connected');
    $('walletLabel').textContent = 'Petra Wallet Connected';
    $('walletAddress').textContent = authorAddress.slice(0,10) + '...' + authorAddress.slice(-6);
    $('walletBtn').classList.add('connected');
    right.textContent = '✓ CONNECTED';
    $('disconnectBtn').style.display = 'block';

    $('message').disabled = false;
    $('unlockDate').disabled = false;
    document.querySelectorAll('.quick-pick-btn').forEach(b => b.disabled = false);
    $('recipient').disabled = false;
    $('sealBtn').disabled = false;
    if (onShelbyNet) clearError();
  } catch (err) {
    right.textContent = 'CONNECT →';
    showError('Connection failed: ' + (err.message || String(err)));
  }
});

$('disconnectBtn').addEventListener('click', async () => {
  await disconnectWallet(authorWallet);
  authorWallet = null; authorAddress = null;
  recipientAddress = null; recipientPublicKey = null;

  $('walletDot').classList.remove('connected');
  $('walletLabel').textContent = 'Connect Petra Wallet to Continue';
  $('walletAddress').textContent = '';
  $('walletBtn').classList.remove('connected');
  $('walletBtnRight').textContent = 'CONNECT →';
  $('disconnectBtn').style.display = 'none';

  $('message').disabled = true;
  $('unlockDate').disabled = true;
  document.querySelectorAll('.quick-pick-btn').forEach(b => b.disabled = true);
  $('recipient').disabled = true;
  $('sealBtn').disabled = true;
  $('recipient').value = '';
  onRecipientChange();
  clearError();
});

// ── Recipient field: async on-chain pubkey lookup, debounced ──
let recipientLookupTimer = null;
let recipientLookupToken = 0;

$('recipient').addEventListener('input', () => {
  clearTimeout(recipientLookupTimer);
  recipientLookupTimer = setTimeout(onRecipientChange, 400);
});

async function onRecipientChange() {
  const val = $('recipient').value.trim();
  const section = $('recipientAuthSection');
  const statusText = $('recipientStatusText');

  recipientAddress = null;
  recipientPublicKey = null;

  if (!val) {
    section.style.display = 'none';
    return;
  }

  if (!/^0x[0-9a-fA-F]{4,64}$/.test(val)) {
    section.style.display = 'block';
    statusText.textContent = 'Enter a valid wallet address (starting with 0x).';
    return;
  }

  section.style.display = 'block';
  statusText.textContent = 'Checking if this address has a registered key...';

  const myToken = ++recipientLookupToken;
  try {
    const pubkey = await getPubkey(val);
    if (myToken !== recipientLookupToken) return; // stale — user kept typing

    if (pubkey) {
      recipientAddress = val;
      recipientPublicKey = pubkey;
      statusText.textContent = '✓ This address has a registered key. The message will be cryptographically bound to it — only they can ever decrypt it.';
    } else {
      statusText.textContent = '⚠ This address has not registered a key yet. Ask them to visit /register.html first, or leave this field blank to seal without recipient binding.';
    }
  } catch (err) {
    if (myToken !== recipientLookupToken) return;
    statusText.textContent = 'Could not check registration: ' + (err.message || String(err));
  }
}

// ── Char count + date defaults ──
$('message').addEventListener('input', () => {
  $('charCount').textContent = $('message').value.length;
});

function toLocalDatetimeInputValue(date) {
  const pad = n => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}
const minUnlock = new Date(Date.now() + 2 * 60000); // at least 2 minutes out
$('unlockDate').min = toLocalDatetimeInputValue(minUnlock);
$('unlockDate').value = toLocalDatetimeInputValue(new Date(Date.now() + 7 * 86400000));

document.querySelectorAll('.quick-pick-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const mins = parseInt(btn.dataset.mins, 10);
    $('unlockDate').value = toLocalDatetimeInputValue(new Date(Date.now() + mins * 60000));
  });
});

// ── Seal ──
$('sealBtn').addEventListener('click', async () => {
  clearError();

  if (CONTRACT_ADDRESS === '__SET_AFTER_PUBLISH__') {
    showError('Contract not deployed yet — see move/DEPLOY.md.');
    return;
  }

  const message = $('message').value.trim();
  const unlockDateStr = $('unlockDate').value;
  const recipientTyped = $('recipient').value.trim();

  if (!authorWallet) { showError('Please connect your Petra wallet first.'); return; }
  if (!message) { showError('Please write a message to seal.'); return; }
  if (!unlockDateStr) { showError('Please set an unlock date.'); return; }
  const unlockTimeSeconds = Math.floor(new Date(unlockDateStr).getTime() / 1000);
  if (unlockTimeSeconds <= Math.floor(Date.now() / 1000)) { showError('Unlock date must be in the future.'); return; }
  if (recipientTyped && !recipientPublicKey) {
    showError('This recipient has not registered a key yet (or the lookup has not finished). Ask them to visit /register.html, or leave the recipient field blank.');
    return;
  }

  const btn = $('sealBtn');
  btn.disabled = true;
  $('progress').classList.add('active');
  $('result').classList.remove('active');

  try {
    ensureCapsuleSeed();
    const blobName = `capsules/${capsuleSeed}.bin`;
    const timeKey = generateTimeKey();

    // Layer 1: AES-256-GCM encrypt with the time_key (chain-enforced release).
    const ciphertextB64 = await encryptMessage(message, timeKey);

    // Layer 2 (optional): if a recipient with a registered key was found,
    // box the layer-1 ciphertext to their public key — asymmetric, so they
    // never needed to be online for this step.
    let dataBytes;
    let recipientBound = false;
    if (recipientPublicKey) {
      const layer1Bytes = new TextEncoder().encode(ciphertextB64);
      const boxedJson = boxToRecipient(layer1Bytes, recipientPublicKey);
      dataBytes = new TextEncoder().encode(boxedJson);
      recipientBound = true;
    } else {
      dataBytes = new TextEncoder().encode(ciphertextB64);
    }

    const expirationMicros = (unlockTimeSeconds + 365 * 24 * 3600) * 1_000_000;

    const uploadResult = await uploadCapsuleToShelby({
      wallet: authorWallet,
      ownerAddress: authorAddress,
      blobName,
      data: dataBytes,
      expirationMicros,
      onProgress: (phase) => {
        if (phase === 'generating-commitments') setStep('step1', 'active-step');
        if (phase === 'registering-onchain') { setStep('step1', 'done'); setStep('step2', 'active-step'); }
        if (phase === 'uploading-bytes') { setStep('step2', 'done'); setStep('step3', 'active-step'); }
        if (phase === 'done') setStep('step3', 'done');
      },
    });

    // Step 4: seal on our time_capsule contract
    setStep('step4', 'active-step');
    const sealTxHash = await sealCapsuleOnChain(authorWallet, {
      timeKeyBytes: timeKey,
      unlockTimeSeconds,
      recipientAddress: recipientAddress || '0x0',
      blobId: uploadResult.merkleRoot,
      blobName,
      recipientBound,
    });
    setStep('step4', 'done');

    // Step 5: confirm + get capsule id
    setStep('step5', 'active-step');
    const capsuleId = await getCapsuleIdFromTx(sealTxHash);
    setStep('step5', 'done');

    const base = window.location.href.replace(/index\.html.*$/, '').replace(/\/$/, '');
    const capsuleUrl = `${base}/open.html?id=${capsuleId}`;

    $('resultUrl').textContent = capsuleUrl;
    $('resultMeta').innerHTML = `
      Capsule ID: <span>#${capsuleId}</span><br>
      Author: <span>${authorAddress.slice(0,12)}...${authorAddress.slice(-6)}</span><br>
      Unlock: <span>${new Date(unlockTimeSeconds * 1000).toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'})} (chain-enforced)</span><br>
      ${recipientAddress ? `Recipient: <span>${recipientAddress.slice(0,12)}...${recipientAddress.slice(-6)} — key cryptographically bound ✓</span><br>` : 'Recipient: <span>Anyone</span><br>'}
      Blob: <span>${blobName}</span><br>
      Seal tx: <a href="https://explorer.aptoslabs.com/txn/${sealTxHash}?network=custom" target="_blank">${sealTxHash.slice(0,10)}...</a>
    `;
    $('result').classList.add('active');
    window._capsuleUrl = capsuleUrl;

  } catch (err) {
    showError('Error: ' + (err.message || String(err)));
    ['step1','step2','step3','step4','step5'].forEach(s => setStep(s, ''));
  } finally {
    btn.disabled = false;
  }
});

$('copyBtn').addEventListener('click', () => {
  navigator.clipboard.writeText(window._capsuleUrl || $('resultUrl').textContent);
  $('copyBtn').textContent = 'Copied ✓';
  setTimeout(() => $('copyBtn').textContent = 'Copy Link', 2000);
});
