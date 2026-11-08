const WS_URL = "wss://chat.example.com/xmpp-websocket";
const DOMAIN = "chat.example.com";
const SALT = new TextEncoder().encode("bazin-chat-open-source-salt-key");

let ws = null;
let e2eeKey = null;
let wsState = 'DISCONNECTED';
let myUsername = '';
let chatHistories = {}; // Format: { "alice@chat...": [ {sender, text, type}, ... ] }
let activeTarget = null;
const seenNonces = new Set();

// --- UI Elements ---
const loginScreen = document.getElementById('login-screen');
const chatScreen = document.getElementById('chat-screen');
const chatBox = document.getElementById('chat-box');
const msgInput = document.getElementById('msg-input');
const statusText = document.getElementById('login-status');

// --- RFC 8439 Native ChaCha20-Poly1305 Implementation ---

function chacha20Block(keyBytes, counter, nonceBytes) {
    const state = new Uint32Array(16);
    state[0] = 0x61707865; state[1] = 0x3320646e;
    state[2] = 0x79622d32; state[3] = 0x6b206574;
    const keyView = new DataView(keyBytes.buffer, keyBytes.byteOffset, keyBytes.byteLength);
    for (let i = 0; i < 8; i++) state[4 + i] = keyView.getUint32(i * 4, true);
    state[12] = counter >>> 0;
    const nonceView = new DataView(nonceBytes.buffer, nonceBytes.byteOffset, nonceBytes.byteLength);
    state[13] = nonceView.getUint32(0, true);
    state[14] = nonceView.getUint32(4, true);
    state[15] = nonceView.getUint32(8, true);
    const working = new Uint32Array(state);
    function qr(a, b, c, d) {
        working[a] = (working[a] + working[b]) >>> 0; working[d] ^= working[a];
        working[d] = (working[d] << 16 | working[d] >>> 16) >>> 0;
        working[c] = (working[c] + working[d]) >>> 0; working[b] ^= working[c];
        working[b] = (working[b] << 12 | working[b] >>> 20) >>> 0;
        working[a] = (working[a] + working[b]) >>> 0; working[d] ^= working[a];
        working[d] = (working[d] << 8 | working[d] >>> 24) >>> 0;
        working[c] = (working[c] + working[d]) >>> 0; working[b] ^= working[c];
        working[b] = (working[b] << 7 | working[b] >>> 25) >>> 0;
    }
    for (let i = 0; i < 10; i++) {
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
    }
    const out = new Uint8Array(64);
    const outView = new DataView(out.buffer);
    for (let i = 0; i < 16; i++) {
        outView.setUint32(i * 4, (working[i] + state[i]) >>> 0, true);
    }
    return out;
}

function chacha20Xor(keyBytes, counter, nonceBytes, inputBytes) {
    const output = new Uint8Array(inputBytes.length);
    let currCounter = counter;
    for (let offset = 0; offset < inputBytes.length; offset += 64) {
        const keyStream = chacha20Block(keyBytes, currCounter++, nonceBytes);
        const blockSize = Math.min(64, inputBytes.length - offset);
        for (let i = 0; i < blockSize; i++) {
            output[offset + i] = inputBytes[offset + i] ^ keyStream[i];
        }
    }
    return output;
}

function poly1305Clamp(rBytes) {
    const clamped = new Uint8Array(rBytes);
    clamped[3] &= 15; clamped[7] &= 15; clamped[11] &= 15; clamped[15] &= 15;
    clamped[4] &= 252; clamped[8] &= 252; clamped[12] &= 252;
    return clamped;
}

function bytesToBigIntLE(bytes) {
    let res = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) {
        res = (res << 8n) | BigInt(bytes[i]);
    }
    return res;
}

function poly1305(msgBytes, key32Bytes) {
    const r = bytesToBigIntLE(poly1305Clamp(key32Bytes.slice(0, 16)));
    const s = bytesToBigIntLE(key32Bytes.slice(16, 32));
    const P = (1n << 130n) - 5n;
    let acc = 0n;
    for (let offset = 0; offset < msgBytes.length; offset += 16) {
        const chunk = msgBytes.slice(offset, offset + 16);
        let n = bytesToBigIntLE(chunk);
        n += (1n << BigInt(8 * chunk.length));
        acc = ((acc + n) * r) % P;
    }
    const tagVal = (acc + s) & ((1n << 128n) - 1n);
    const tag = new Uint8Array(16);
    let temp = tagVal;
    for (let i = 0; i < 16; i++) {
        tag[i] = Number(temp & 0xffn);
        temp >>= 8n;
    }
    return tag;
}

function makeMacData(ciphertext) {
    const padLen = (16 - (ciphertext.length % 16)) % 16;
    const macData = new Uint8Array(ciphertext.length + padLen + 16);
    macData.set(ciphertext, 0);
    const view = new DataView(macData.buffer, macData.byteOffset, macData.byteLength);
    view.setUint32(ciphertext.length + padLen + 8, ciphertext.length, true);
    return macData;
}

function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

// --- Hardened Crypto & Escaping ---

function escapeXml(unsafe) {
    return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&apos;");
}

async function deriveKey(passphrase) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw", enc.encode(passphrase), "PBKDF2", false, ["deriveBits"]
    );
    const keyBuffer = await crypto.subtle.deriveBits({
        name: "PBKDF2",
        salt: SALT,
        iterations: 200000,
        hash: "SHA-256"
    }, keyMaterial, 256);
    return new Uint8Array(keyBuffer);
}

function encryptMsg(text) {
    const pt = new TextEncoder().encode(text);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const block0 = chacha20Block(e2eeKey, 0, nonce);
    const polyKey = block0.slice(0, 32);
    const ct = chacha20Xor(e2eeKey, 1, nonce, pt);
    const macData = makeMacData(ct);
    const tag = poly1305(macData, polyKey);

    const combined = new Uint8Array(12 + ct.length + 16);
    combined.set(nonce, 0);
    combined.set(ct, 12);
    combined.set(tag, 12 + ct.length);

    let binary = '';
    for (let i = 0; i < combined.length; i++) binary += String.fromCharCode(combined[i]);
    return "E2EE:" + btoa(binary);
}

function decryptMsg(payload) {
    if (!payload.startsWith("E2EE:")) return `[UNENCRYPTED] ${escapeXml(payload)}`;
    try {
        const binary = atob(payload.substring(5));
        const raw = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) raw[i] = binary.charCodeAt(i);
        if (raw.length < 28) return "[DECRYPTION FAILED - Short Payload]";

        const nonce = raw.slice(0, 12);
        const nonceHex = Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join('');
        
        // Replay Protection Check
        if (seenNonces.has(nonceHex)) {
            console.error("[SECURITY] Blocked replayed ciphertext. Nonce:", nonceHex);
            return "[SECURITY ALERT - Replayed Message Blocked]";
        }

        const ct = raw.slice(12, raw.length - 16);
        const tag = raw.slice(raw.length - 16);
        const block0 = chacha20Block(e2eeKey, 0, nonce);
        const polyKey = block0.slice(0, 32);
        const macData = makeMacData(ct);
        const expectedTag = poly1305(macData, polyKey);
        
        if (!timingSafeEqual(tag, expectedTag)) {
            return "[DECRYPTION FAILED - Wrong E2EE Key]";
        }

        seenNonces.add(nonceHex);
        const pt = chacha20Xor(e2eeKey, 1, nonce, ct);
        return new TextDecoder().decode(pt);
    } catch (e) {
        return "[DECRYPTION FAILED - Malformed Data]";
    }
}

// --- Multi-Target UI State Management ---

function renderTargetList() {
    const list = document.getElementById('target-list');
    list.innerHTML = '';
    for (const jid in chatHistories) {
        const btn = document.createElement('button');
        btn.className = 'target-btn' + (jid === activeTarget ? ' active' : '');
        btn.textContent = jid;
        btn.onclick = () => {
            activeTarget = jid;
            renderTargetList(); 
            renderChat();       
        };
        list.appendChild(btn);
    }
}

function renderChat() {
    chatBox.innerHTML = '';
    if (!activeTarget) return;
    
    const history = chatHistories[activeTarget] || [];
    history.forEach(msg => {
        const div = document.createElement('div');
        div.className = 'msg';
        const senderSpan = document.createElement('span');
        senderSpan.className = msg.type;
        senderSpan.textContent = `[${msg.sender}] `;
        div.appendChild(senderSpan);
        div.appendChild(document.createTextNode(msg.text));
        chatBox.appendChild(div);
    });
    chatBox.scrollTop = chatBox.scrollHeight;
}

function printToChat(sender, text, type = 'msg-sender', targetJid = null) {
    const route = targetJid || activeTarget;
    if (!route) return;

    if (!chatHistories[route]) {
        chatHistories[route] = [];
        renderTargetList();
    }
    
    chatHistories[route].push({ sender, text, type });
    
    if (route === activeTarget) {
        renderChat();
    } else {
        renderTargetList(); 
    }
}

// --- Event Listeners ---

document.getElementById('add-target-btn').addEventListener('click', () => {
    let newTarget = document.getElementById('new-target').value.trim();
    if (!newTarget) return;
    if (!newTarget.includes('@')) newTarget += `@${DOMAIN}`;
    
    if (!chatHistories[newTarget]) chatHistories[newTarget] = [];
    activeTarget = newTarget;
    document.getElementById('new-target').value = '';
    
    renderTargetList();
    renderChat();
});

document.getElementById('logout-btn').addEventListener('click', () => {
    if (ws) ws.close();
    e2eeKey = null;
    seenNonces.clear();
    chatHistories = {};
    activeTarget = null;
    document.getElementById('password').value = '';
    document.getElementById('secret').value = '';
    chatScreen.style.display = 'none';
    loginScreen.style.display = 'block';
});

document.getElementById('change-key-btn').addEventListener('click', async () => {
    const newSecret = prompt("Enter new E2EE Passphrase (messages using the old key will fail to decrypt):");
    if (newSecret) {
        e2eeKey = await deriveKey(newSecret);
        seenNonces.clear();
        printToChat('System', 'Live key swapped. All new outbound/inbound messages will use this key.', 'msg-system', activeTarget);
    }
});

function sendXml(xmlStr) {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(xmlStr);
}

document.getElementById('msg-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        const text = e.target.value.trim();
        if (!text) return;
        if (!activeTarget || activeTarget === 'System') {
            alert("Cannot send messages to the System tab. Add a Target JID from the left menu.");
            return;
        }
        const ciphertext = encryptMsg(text);
        const stanza = `<message to="${activeTarget}" type="chat" xmlns="jabber:client"><body>${ciphertext}</body></message>`;
        sendXml(stanza);
        printToChat('Me', text, 'msg-me', activeTarget);
        e.target.value = '';
    }
});

// --- Core XMPP Network Initialization ---

document.getElementById('connect-btn').addEventListener('click', async () => {
    let jid = document.getElementById('jid').value.trim();
    const pass = document.getElementById('password').value;
    const secret = document.getElementById('secret').value;

    if (!jid || !pass || !secret) {
        statusText.textContent = "Fill in all fields.";
        return;
    }

    if (!jid.includes('@')) jid += `@${DOMAIN}`;
    myUsername = jid.split('@')[0];

    statusText.textContent = "Deriving keys...";
    e2eeKey = await deriveKey(secret);

    statusText.textContent = "Opening WebSocket...";
    try {
        ws = new WebSocket(WS_URL, "xmpp");
    } catch (err) {
        statusText.textContent = "Socket creation failed: " + err.message;
        return;
    }

    ws.onopen = () => {
        wsState = 'WAIT_FEATURES_1';
        sendXml(`<open xmlns="urn:ietf:params:xml:ns:xmpp-framing" to="${DOMAIN}" version="1.0"/>`);
    };

    ws.onmessage = async (e) => {
        const frame = e.data;

        if (wsState === 'WAIT_FEATURES_1') {
            if (frame.includes('features')) {
                const authStr = `\0${myUsername}\0${pass}`;
                const b64Auth = btoa(authStr);
                sendXml(`<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="PLAIN">${b64Auth}</auth>`);
                wsState = 'WAIT_AUTH';
            }
        } 
        else if (wsState === 'WAIT_AUTH') {
            if (frame.includes('<success')) {
                wsState = 'WAIT_FEATURES_2';
                sendXml(`<open xmlns="urn:ietf:params:xml:ns:xmpp-framing" to="${DOMAIN}" version="1.0"/>`);
            } else if (frame.includes('<failure')) {
                statusText.textContent = "Authentication Failed.";
                ws.close();
            }
        }
        else if (wsState === 'WAIT_FEATURES_2') {
            if (frame.includes('features') || frame.includes('bind')) {
                sendXml(`<iq type="set" id="bind_1" xmlns="jabber:client"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"><resource>web</resource></bind></iq>`);
                wsState = 'WAIT_BIND';
            }
        }
        else if (wsState === 'WAIT_BIND') {
            if (frame.includes('bind_1') || frame.includes('type="result"') || frame.includes("type='result'")) {
                sendXml('<presence xmlns="jabber:client"/>');
                wsState = 'CONNECTED';
                
                chatHistories = { "System": [] };
                activeTarget = "System";
                renderTargetList();
                renderChat();
                
                loginScreen.style.display = 'none';
                chatScreen.style.display = 'flex'; 
                printToChat('System', 'Connected via Zero-Knowledge WebSocket.', 'msg-system', 'System');
            }
        }
        else if (wsState === 'CONNECTED') {
            const parser = new DOMParser();
            const doc = parser.parseFromString(frame, "text/xml");
            const root = doc.documentElement;
            if (!root) return;

            if (root.tagName === 'iq' && root.querySelector('ping')) {
                const id = escapeXml(root.getAttribute('id') || '1');
                sendXml(`<iq type="result" to="${DOMAIN}" id="${id}" xmlns="jabber:client"/>`);
            }
            else if (root.tagName === 'message') {
                const bodyEl = root.querySelector('body');
                if (bodyEl && bodyEl.textContent) {
                    const senderFull = root.getAttribute('from') || 'unknown';
                    const bareJid = escapeXml(senderFull.split('/')[0]); 
                    const decrypted = decryptMsg(bodyEl.textContent);
                    printToChat(bareJid, decrypted, 'msg-sender', bareJid);
                }
            }
        }
    };

    ws.onclose = () => {
        if (wsState === 'CONNECTED') {
            printToChat('System', 'Disconnected from server.', 'msg-system', 'System');
            document.getElementById('status-indicator').textContent = '🔴 Disconnected';
        }
        wsState = 'DISCONNECTED';
    };
});
