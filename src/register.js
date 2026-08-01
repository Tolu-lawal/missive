import { waitForWallet, connectWallet, disconnectWallet, switchToShelbyNet, getCurrentNetwork } from './lib/wallet.js';
import { deriveX25519Keypair, bytesToBase64 } from './lib/crypto.js';
import { registerPubkey, hasPubkey, CONTRACT_ADDRESS } from './lib/contract.js';

const $ = (id) => document.getElementById(id);

let authorWallet = null;
let authorAddress = null;

function showError(msg) { $('errorMsg').textContent = msg; $('errorMsg').classList.add('active'); }
function clearError() { $('errorMsg').classList.remove('active'); }

function showStatus(text) {
  $('statusBox').style.display = 'block';
  $('statusText').textContent = text;
}

// ── Contract deployment guard ──
if (CONTRACT_ADDRESS === '__SET_AFTER_PUBLISH__') {
  showError('The time capsule contract has not been deployed yet. See move/DEPLOY.md.');
}

async function refreshStatus() {
  if (!authorAddress) return;
  try {
    const already = await hasPubkey(authorAddress);
    if (already) {
      showStatus('✓ You already have a key registered. Signing again below will rotate it to a new one.');
    } else {
      showStatus('You have not registered a key yet. Click below to set one up.');
    }
  } catch (err) {
    showStatus('Could not check registration status: ' + (err.message || String(err)));
  }
}

// ── Wallet connect ──
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
  const net = await getCurrentNetwork(wallet);
    const onShelbyNet = net && (
      String(net.chainId) === '114' ||
      String(net.chainId) === '0x72' ||
      String(net.name || '').toLowerCase() === 'shelbynet' ||
      String(net.url || '').includes('shelbynet.shelby.xyz')
    );
    authorWallet = wallet;

    if (!onShelbyNet) {
      showError('Petra is not on ShelbyNet (currently: ' + (net?.name || net?.chainId || 'unknown') + '). Please open Petra and manually switch the network to "Shelbynet" before registering, then reconnect.');
    }

    $('walletDot').classList.add('connected');
    $('walletLabel').textContent = 'Petra Wallet Connected';
    $('walletAddress').textContent = authorAddress.slice(0,10) + '...' + authorAddress.slice(-6);
    $('walletBtn').classList.add('connected');
    right.textContent = '✓ CONNECTED';
    $('disconnectBtn').style.display = 'block';
    $('registerBtn').disabled = false;

    if (onShelbyNet) {
      clearError();
      await refreshStatus();
    }
  } catch (err) {
    right.textContent = 'CONNECT →';
    showError('Connection failed: ' + (err.message || String(err)));
  }
});

$('disconnectBtn').addEventListener('click', async () => {
  await disconnectWallet(authorWallet);
  authorWallet = null; authorAddress = null;

  $('walletDot').classList.remove('connected');
  $('walletLabel').textContent = 'Connect Petra Wallet to Continue';
  $('walletAddress').textContent = '';
  $('walletBtn').classList.remove('connected');
  $('walletBtnRight').textContent = 'CONNECT →';
  $('disconnectBtn').style.display = 'none';
  $('registerBtn').disabled = true;
  $('statusBox').style.display = 'none';
  $('result').classList.remove('active');
  clearError();
});

// ── Register ──
$('registerBtn').addEventListener('click', async () => {
  clearError();

  if (CONTRACT_ADDRESS === '__SET_AFTER_PUBLISH__') {
    showError('Contract not deployed yet — see move/DEPLOY.md.');
    return;
  }
  if (!authorWallet) { showError('Please connect your Petra wallet first.'); return; }

  const btn = $('registerBtn');
  btn.disabled = true;
  showStatus('Deriving your key from a wallet signature...');

  try {
    const keypair = await deriveX25519Keypair(authorWallet);
    showStatus('Publishing your public key on-chain — check Petra to sign...');

    const txHash = await registerPubkey(authorWallet, keypair.publicKey);

    $('resultMeta').innerHTML = `
      Address: <span>${authorAddress.slice(0,12)}...${authorAddress.slice(-6)}</span><br>
      Public key: <span>${bytesToBase64(keypair.publicKey)}</span><br>
      Register tx: <a href="https://explorer.aptoslabs.com/txn/${txHash}?network=custom" target="_blank">${txHash.slice(0,10)}...</a>
    `;
    $('result').classList.add('active');
    showStatus('✓ Key registered. Anyone can now seal a message addressed to your wallet.');
  } catch (err) {
    showError('Registration failed: ' + (err.message || String(err)));
    showStatus('Registration did not complete — try again.');
  } finally {
    btn.disabled = false;
  }
});
