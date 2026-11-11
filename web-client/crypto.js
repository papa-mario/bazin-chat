// crypto.js
const SALT = new TextEncoder().encode("bazin-chat-open-source-salt-key");
const seenNonces = new Set();

export async function deriveKey(passphrase) {
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

// Minimal ChaCha20 implementation helpers
function rotl(a, b) {
    return ((a << b) | (a >>> (32 - b))) >>> 0;
}

function quarterRound(x, a, b, c, d) {
    x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 16);
    x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 12);
    x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 8);
    x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 7);
}

function chacha20Block(key, counter, nonce) {
    const state = new Uint32Array(16);
    state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
    
    const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
    for (let i = 0; i < 8; i++) state[4 + i] = keyView.getUint32(i * 4, true);
    
    state[12] = counter;
    const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
    for (let i = 0; i < 3; i++) state[13 + i] = nonceView.getUint32(i * 4, true);

    const workingState = new Uint32Array(state);
    for (let i = 0; i < 10; i++) {
        quarterRound(workingState, 0, 4, 8, 12);
        quarterRound(workingState, 1, 5, 9, 13);
        quarterRound(workingState, 2, 6, 10, 14);
        quarterRound(workingState, 3, 7, 11, 15);
        quarterRound(workingState, 0, 5, 10, 15);
        quarterRound(workingState, 1, 6, 11, 12);
        quarterRound(workingState, 2, 7, 8, 13);
        quarterRound(workingState, 3, 4, 9, 14);
    }
    
    for (let i = 0; i < 16; i++) workingState[i] = (workingState[i] + state[i]) >>> 0;
    return new Uint8Array(workingState.buffer);
}

function chacha20Xor(key, counter, nonce, data) {
    const out = new Uint8Array(data.length);
    let block;
    for (let i = 0; i < data.length; i++) {
        if (i % 64 === 0) {
            block = chacha20Block(key, counter + Math.floor(i / 64), nonce);
        }
        out[i] = data[i] ^ block[i % 64];
    }
    return out;
}

// Minimal Poly1305 implementation helpers
function poly1305Clamp(r) {
    const clamped = new Uint8Array(r);
    clamped[3] &= 15;
    clamped[7] &= 15;
    clamped[11] &= 15;
    clamped[15] &= 15;
    clamped[4] &= 252;
    clamped[8] &= 252;
    clamped[12] &= 252;
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


function makeMacData(ct) {
    const padLen = (16 - (ct.length % 16)) % 16;
    const lenBlock = new ArrayBuffer(16);
    new DataView(lenBlock).setBigUint64(8, BigInt(ct.length), true);
    
    const macData = new Uint8Array(ct.length + padLen + 16);
    macData.set(ct, 0);
    macData.set(new Uint8Array(lenBlock), ct.length + padLen);
    return macData;
}

function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) result |= a[i] ^ b[i];
    return result === 0;
}

function escapeXml(unsafe) {
    return unsafe.replace(/[<>&'"]/g, c => {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
        }
    });
}

// Note: encryptMsg now takes the key as a parameter
export async function encryptMsg(text, key) {
    const pt = new TextEncoder().encode(text);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const block0 = chacha20Block(key, 0, nonce);
    const polyKey = block0.slice(0, 32);
    const ct = chacha20Xor(key, 1, nonce, pt);
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

// Note: decryptMsg now takes the key as a parameter
export async function decryptMsg(payload, key) {
    if (!payload.startsWith("E2EE:")) return `[UNENCRYPTED] ${escapeXml(payload)}`;
    try {
        const binary = atob(payload.substring(5));
        const raw = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) raw[i] = binary.charCodeAt(i);
        if (raw.length < 28) return "[DECRYPTION FAILED - Short Payload]";

        const nonce = raw.slice(0, 12);
        const nonceHex = Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join('');
        
        if (seenNonces.has(nonceHex)) {
            console.error("[SECURITY] Blocked replayed ciphertext. Nonce:", nonceHex);
            return "[SECURITY ALERT - Replayed Message Blocked]";
        }

        const ct = raw.slice(12, raw.length - 16);
        const tag = raw.slice(raw.length - 16);
        const block0 = chacha20Block(key, 0, nonce);
        const polyKey = block0.slice(0, 32);
        const macData = makeMacData(ct);
        const expectedTag = poly1305(macData, polyKey);
        
        if (!timingSafeEqual(tag, expectedTag)) {
            return "[DECRYPTION FAILED - Wrong E2EE Key]";
        }

        seenNonces.add(nonceHex);
        const pt = chacha20Xor(key, 1, nonce, ct);
        return new TextDecoder().decode(pt);
    } catch (e) {
        return "[DECRYPTION FAILED - Malformed Data]";
    }
}
