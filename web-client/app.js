// app.js
import { deriveKey, encryptMsg, decryptMsg } from './crypto.js';
import { BazinXMPP } from './xmpp.js';

let appKey = null;
let xmppClient = null;
let myUsername = null;
let activeTarget = null;
const chatHistory = {};
const createdTabs = new Set();

document.getElementById('connect-btn').addEventListener('click', async () => {
    const fullJid = document.getElementById('jid').value.trim();
    const password = document.getElementById('password').value;
    const secret = document.getElementById('secret').value;

    if (!fullJid || !password || !secret) {
        document.getElementById('login-status').innerText = "All fields required.";
        return;
    }

    let [username, domain] = fullJid.split('@');
    if (!domain) {
        domain = window.location.hostname;
    }
    myUsername = username.toLowerCase();

    try {
        document.getElementById('login-status').innerText = "Deriving key...";
        appKey = await deriveKey(secret);
        
        document.getElementById('login-status').innerText = "Authenticating XMPP...";
        xmppClient = new BazinXMPP(
            domain,
            myUsername,
            password,
            () => {
                document.getElementById('login-screen').style.display = 'none';
                document.getElementById('chat-screen').style.display = 'flex';
            },
            (errMsg) => {
                document.getElementById('login-status').innerText = errMsg;
            }
        );
        
        xmppClient.onMessageReceived = handleIncomingMessage;
    } catch (err) {
        document.getElementById('login-status').innerText = "Connection failed.";
        console.error(err);
    }
});

function normalizeTarget(rawTarget) {
    const clean = rawTarget.trim().toLowerCase();
    if (!clean) return '';
    if (clean.startsWith('#')) return clean;
    if (!clean.includes('@')) return `${clean}@${xmppClient.domain}`;
    return clean;
}

function ensureTargetTab(targetVal) {
    if (!chatHistory[targetVal]) {
        chatHistory[targetVal] = [];
    }

    if (!createdTabs.has(targetVal)) {
        createdTabs.add(targetVal);

        const btn = document.createElement('button');
        btn.innerText = targetVal;
        btn.style.width = '100%';
        btn.onclick = () => switchTarget(targetVal);
        document.getElementById('target-list').appendChild(btn);

        if (targetVal.startsWith('#')) {
            const roomName = targetVal.substring(1);
            xmppClient.joinGroup(roomName, myUsername);
        } else {
            // Send directed presence to bypass Prosody bare-JID routing restrictions
            xmppClient.sendRaw(`<presence to="${targetVal}" xmlns="jabber:client"/>`);
        }
    }
}

async function handleIncomingMessage(xmlString) {
    const fromMatch = xmlString.match(/from=['"]([^'"]+)['"]/);
    const bodyMatch = xmlString.match(/<body[^>]*>([\s\S]*?)<\/body>/);
    const typeMatch = xmlString.match(/type=['"]([^'"]+)['"]/);

    if (fromMatch && bodyMatch) {
        const fromStr = fromMatch[1];
        const payload = bodyMatch[1].trim();
        const isGroup = typeMatch && typeMatch[1] === 'groupchat';

        let targetId, senderNick;

        if (isGroup) {
            const parts = fromStr.split('/');
            const roomName = parts[0].split('@')[0].toLowerCase();
            targetId = `#${roomName}`;
            senderNick = (parts[1] || 'unknown').toLowerCase();
            
            if (senderNick === myUsername) return; 
        } else {
            targetId = fromStr.split('/')[0].toLowerCase();
            senderNick = targetId.split('@')[0];
        }

        const plaintext = await decryptMsg(payload, appKey);
        saveAndRenderMessage(targetId, senderNick, plaintext);
    }
}

document.getElementById('add-target-btn').addEventListener('click', () => {
    const rawVal = document.getElementById('new-target').value;
    const targetVal = normalizeTarget(rawVal);
    if (!targetVal) return;

    ensureTargetTab(targetVal);
    switchTarget(targetVal);
    document.getElementById('new-target').value = '';
});

function switchTarget(target) {
    activeTarget = target;
    const box = document.getElementById('chat-box');
    box.innerHTML = '';

    const header = document.createElement('div');
    header.style.cssText = 'color: #FFFFFF; border-bottom: 1px dashed #FFFFFF; margin-bottom: 10px;';
    header.textContent = `--- Chatting with ${target} ---`;
    box.appendChild(header);
    
    if (chatHistory[target]) {
        chatHistory[target].forEach(msg => appendMessageToBox(msg.author, msg.text));
    }
}

document.getElementById('msg-input').addEventListener('keypress', async (e) => {
    if (e.key === 'Enter') {
        const text = e.target.value.trim();
        if (!text || !activeTarget) return;

        const ciphertext = await encryptMsg(text, appKey);

        if (activeTarget.startsWith('#')) {
            const roomName = activeTarget.substring(1);
            xmppClient.sendGroupMessage(roomName, ciphertext);
        } else {
            xmppClient.sendDirectMessage(activeTarget, ciphertext);
        }

        saveAndRenderMessage(activeTarget, myUsername, text);
        e.target.value = '';
    }
});

function saveAndRenderMessage(target, author, text) {
    ensureTargetTab(target);
    chatHistory[target].push({ author, text });

    if (!activeTarget) {
        switchTarget(target);
    } else if (activeTarget === target) {
        appendMessageToBox(author, text);
    }
}

function appendMessageToBox(author, text) {
    const box = document.getElementById('chat-box');
    const isMe = author === myUsername;
    const color = isMe ? '#00ffff' : '#ff00ff';

    const row = document.createElement('div');
    row.style.marginBottom = '5px';

    const authorSpan = document.createElement('span');
    authorSpan.style.color = color;
    authorSpan.textContent = `[${author}] `;

    const textNode = document.createTextNode(text);

    row.appendChild(authorSpan);
    row.appendChild(textNode);
    box.appendChild(row);
    box.scrollTop = box.scrollHeight;
}

// --- TOP BAR CONTROLS ---
document.getElementById('logout-btn').addEventListener('click', () => {
    if (xmppClient && xmppClient.ws) xmppClient.ws.close();
    window.location.reload();
});

document.getElementById('change-key-btn').addEventListener('click', async () => {
    const newSecret = prompt("Enter new encryption key for future messages:");
    if (newSecret && newSecret.trim() !== "") {
        appKey = await deriveKey(newSecret.trim());
        alert("Encryption key successfully updated.");
    }
});
