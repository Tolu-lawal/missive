import { waitForWallet, connectWallet, signMessage } from './lib/wallet.js';
import { decryptMessage, deriveX25519Keypair, unboxFromSender } from './lib/crypto.js';
import { downloadCapsuleFromShelby } from './lib/shelby.js';
import { getCapsuleInfo, getTimeKey, CONTRACT_ADDRESS } from './lib/contract.js';

const $ = (id) => document.getElementById(id);

const params = new URLSearchParams(window.location.search);
const capsuleId = params.get('id');

let info = null;        // on-chain capsule metadata
let connectedWallet = null;
let connectedAddress = null;
let countdownInterval = null;

function showFatalError(title, body) {
  $('loadingState').style.display = 'none';
  $('walletGate').classList.remove('active');
  $('errorTitle').textContent = title;
  $('errorBody').innerHTML = body;
  $('errorState').classList.add('active');
}

// ── Particles ──
function burst() {
  const c = $('particles');
  for (let i = 0; i < 50; i++) {
    const p = document.createElement('div');
    p.className = 'particle';
    p.style.left = Math.random() * 100 + 'vw';
    p.style.top = '-20px';
    p.style.animationDuration = (Math.random() * 2 + 1) + 's';
    p.style.animationDelay = Math.random() * 0.5 + 's';
    p.style.background = Math.random() > 0.5 ? '#c9a84c' : '#f0e6d3';
    const sz = (Math.random() * 4 + 2) + 'px';
    p.style.width = p.style.height = sz;
    c.appendChild(p);
    setTimeout(() => p.remove(), 3500);
  }
}

async function typewrite(el, text, speed = 18) {
  el.textContent = ''; el.classList.add('typewriter');
  for (let i = 0; i < text.length; i++) { el.textContent += text[i]; await new Promise(r => setTimeout(r, speed)); }
  el.classList.remove('typewriter');
}

function updateCountdown(targetSeconds) {
  const diff = targetSeconds * 1000 - Date.now();
  if (diff <= 0) return true;
  const d = Math.floor(diff / 86400000), h = Math.floor((diff % 86400000) / 3600000),
        m = Math.floor((diff % 3600000) / 60000), s = Math.floor((diff % 60000) / 1000);
  [['cdDays', d], ['cdHours', h], ['cdMins', m], ['cdSecs', s]].forEach(([id, val]) => {
    const el = $(id), v = String(val).padStart(2, '0');
    if (el.textContent !== v) { el.textContent = v; el.classList.remove('tick'); void el.offsetWidth; el.classList.add('tick'); }
  });
  return false;
}

async function attemptReveal() {
  clearInterval(countdownInterval);
  $('lockedState').classList.remove('active');
  burst();
  $('revealedState').classList.add('active');

  $('metaAuthor').textContent = info.author.slice(0, 14) + '...';
  $('metaSealed').textContent = new Date(info.createdAt * 1000).toLocaleDateString();
  $('metaBlob').textContent = info.blobName;

  await new Promise(r => setTimeout(r, 400));
  burst();

  try {
    // 1. THE ENFORCEMENT CALL — the Move contract itself checks the clock.
    //    If it's not actually time yet (e.g. local clock drift), this
    //    throws and we just keep waiting rather than showing garbage.
    let timeKeyBytes;
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        timeKeyBytes = await getTimeKey(capsuleId);
        break;
      } catch (err) {
        if (String(err.message).includes('NOT_YET_TIME') && attempt < 4) {
          await new Promise(r => setTimeout(r, 2000));
          continue;
        }
        throw err;
      }
    }

    // 2. Download the real encrypted blob from ShelbyNet
    const rawBytes = await downloadCapsuleFromShelby({ ownerAddress: info.author, blobName: info.blobName });
    const rawString = rawBytes instanceof Uint8Array
      ? new TextDecoder().decode(rawBytes)
      : typeof rawBytes === 'string'
        ? rawBytes
        : new TextDecoder().decode(new Uint8Array(Object.values(rawBytes)));

    // 3. If recipient-bound, this blob is a layer-2 "box" — unwrap it first
    //    using the recipient's X25519 private key (re-derived from the same
    //    deterministic wallet signature used at registration) to recover the
    //    layer-1 AES ciphertext underneath.
    let ciphertextB64;
    if (info.recipientBound) {
      const keypair = await deriveX25519Keypair(connectedWallet);
      const layer1Bytes = unboxFromSender(rawString, keypair.secretKey);
      ciphertextB64 = new TextDecoder().decode(layer1Bytes);
    } else {
      ciphertextB64 = rawString;
    }

    // 4. Decrypt layer 1 with the chain-released time_key.
    const plaintext = await decryptMessage(ciphertextB64, timeKeyBytes);
    await typewrite($('messageText'), plaintext, 18);
    $('messageFrom').textContent = '— ' + info.author.slice(0, 12) + '...' + info.author.slice(-6);

  } catch (err) {
    $('messageText').textContent = '[Could not reveal: ' + (err.message || String(err)) + ']';
    $('messageText').style.color = 'var(--muted)';
  }
}

function showLocked() {
  $('walletGate').classList.remove('active');
  $('lockedState').classList.add('active');

  $('infoViewer').textContent = connectedAddress.slice(0, 10) + '...' + connectedAddress.slice(-6) + ' ✓';
  $('infoAuthor').textContent = info.author.slice(0, 14) + '...';
  $('infoUnlock').textContent = new Date(info.unlockTime * 1000).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  $('infoCapsuleId').textContent = '#' + capsuleId;
  $('unlockDisplay').textContent = new Date(info.unlockTime * 1000).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  if (info.recipientBound) $('recipientBoundNote').style.display = 'block';

  updateCountdown(info.unlockTime);
  countdownInterval = setInterval(() => {
    if (updateCountdown(info.unlockTime)) {
      clearInterval(countdownInterval);
      attemptReveal();
    }
  }, 1000);
}

$('gateBtn').addEventListener('click', async () => {
  const btn = $('gateBtn');
  btn.textContent = 'Detecting wallet...';
  btn.disabled = true;

  const wallet = await waitForWallet(3000);
  if (!wallet) {
    btn.textContent = 'Connect Petra Wallet';
    btn.disabled = false;
    window.open('https://petra.app/', '_blank');
    $('gateStatus').innerHTML = '<span style="color:#e88">Petra not detected. Enable it for this site and refresh.</span>';
    return;
  }

  btn.textContent = 'Connecting...';

  try {
    connectedAddress = await connectWallet(wallet);
    connectedWallet = wallet;

    // Sign to prove identity (not strictly required by the contract for
    // public capsules, but good practice — separate from the deterministic
    // X25519 derivation signature used for recipient-bound capsules).
    try { await signMessage(wallet, 'Opening Shelby Time Capsule #' + capsuleId, Date.now().toString()); } catch (e) { /* optional */ }

    $('gateStatus').innerHTML = '<span>✓ Verified: ' + connectedAddress.slice(0, 10) + '...' + connectedAddress.slice(-6) + '</span>';

    if (info.recipientBound && info.recipient !== '0x0' && info.recipient.toLowerCase() !== connectedAddress.toLowerCase()) {
      $('walletGate').classList.remove('active');
      $('wrongWallet').classList.add('active');
      return;
    }

    if (Date.now() / 1000 >= info.unlockTime) {
      $('walletGate').classList.remove('active');
      await attemptReveal();
    } else {
      showLocked();
    }
  } catch (err) {
    btn.textContent = 'Connect Petra Wallet';
    btn.disabled = false;
    $('gateStatus').innerHTML = '<span style="color:#e88">Error: ' + (err.message || String(err)) + '</span>';
  }
});

// ── Init ──
async function init() {
  if (CONTRACT_ADDRESS === '__SET_AFTER_PUBLISH__') {
    showFatalError('Contract Not Deployed', 'The time capsule Move contract has not been published yet.<br>See move/DEPLOY.md.');
    return;
  }

  if (!capsuleId) {
    showFatalError('No Capsule Specified', 'This link is missing a capsule ID.');
    return;
  }

  try {
    info = await getCapsuleInfo(capsuleId);
  } catch (err) {
    showFatalError('Capsule Not Found', 'No capsule exists on-chain with ID #' + capsuleId + '.<br>' + (err.message || ''));
    return;
  }

  $('loadingState').style.display = 'none';
  if (info.recipient && info.recipient !== '0x0') {
    $('gateSub').innerHTML = 'This capsule was sealed for a specific wallet.<br>Connect your Petra wallet to verify you\'re the intended recipient.';
  }
  $('walletGate').classList.add('active');
}

// ── Link input handler ──
const linkInput = $('linkInputSection');
const capsuleInput = $('capsuleLinkInput');
const openBtn = $('openCapsuleBtn');

if (linkInput && !capsuleId) {
  // No capsule ID in URL — show the link input instead
  $('loadingState').style.display = 'none';
  linkInput.style.display = 'block';
}

openBtn?.addEventListener('click', () => {
  const val = capsuleInput.value.trim();
  if (!val) return;
  try {
    const url = new URL(val);
    const id = url.searchParams.get('id');
    if (!id) { alert('No capsule ID found in that link.'); return; }
    window.location.href = `/open.html?id=${id}`;
  } catch {
    alert('Invalid link. Paste the full capsule URL.');
  }
});

capsuleInput?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') openBtn.click();
});

init();
