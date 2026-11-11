// app.js
import { deriveKey, encryptMsg, decryptMsg } from './crypto.js';
import { BazinXMPP } from './xmpp.js';

let appKey = null;
let xmppClient = null;
let myUsername = null;
let activeTarget = null; 
const chatHistory = {}; // Stores messages per target: { '#general': [...], 'alice@domain': [...] }

// --- 1. LOGIN & INITIALIZATION ---
document.getElementById('connect-btn').addEventListener('click', async () => {
    const fullJid = document.getElementById('jid').value;
    const password = document.getElementById('password').value;
    const secret = document.getElementById('secret').value;

    if (!fullJid || !password || !secret) {
        document.getElementById('login-status').innerText = "All fields required.";
        return;
    }

    const [username, domain] = fullJid.split('@');
    myUsername = username;

    try {
        document.getElementById('login-status').innerText = "Deriving key...";
        appKey = await deriveKey(secret);
        
        document.getElementById('login-status').innerText = "Connecting...";
        xmppClient = new BazinXMPP(domain, username, password);
        
        // Setup XMPP listener
        xmppClient.onMessageReceived = handleIncomingMessage;

        // Swap Screens
        document.getElementById('login-screen').style.display = 'none';
        document.getElementById('chat-screen').style.display = 'flex';
    } catch (err) {
        document.getElementById('login-status').innerText = "Connection failed.";
        console.error(err);
    }
});

// --- 2. HANDLING INCOMING MESSAGES ---
async function handleIncomingMessage(xmlString) {
    // Extract metadata using basic regex (XMPP stanzas are XML)
    const fromMatch = xmlString.match(/from="([^"]+)"/);
    const bodyMatch = xmlString.match(/<body>(.*?)<\/body>/);
    const typeMatch = xmlString.match(/type="([^"]+)"/);

    if (fromMatch && bodyMatch) {
        const fromStr = fromMatch[1];
        const payload = bodyMatch[1];
        const isGroup = typeMatch && typeMatch[1] === 'groupchat';

        let targetId, senderNick;

        if (isGroup) {
            // MUC Format: roomName@conference.domain.com/NickName
            const parts = fromStr.split('/');
            const roomName = parts[0].split('@')[0];
            targetId = `#${roomName}`;
            senderNick = parts[1]; 
            
            // XMPP MUCs echo your own messages back to you. Ignore our own echoes.
            if (senderNick === myUsername) return; 
        } else {
            // Direct Message Format: user@domain.com/Resource
            targetId = fromStr.split('/')[0];
            senderNick = targetId.split('@')[0];
        }

        const plaintext = await decryptMsg(payload, appKey);
        saveAndRenderMessage(targetId, senderNick, plaintext);
    }
}

// --- 3. TARGET MANAGER (SIDEBAR) ---
document.getElementById('add-target-btn').addEventListener('click', () => {
    const targetVal = document.getElementById('new-target').value.trim();
    if (!targetVal) return;

    if (!chatHistory[targetVal]) {
        // Initialize history for this new target
        chatHistory[targetVal] = [];
        
        // Create Sidebar Button
        const btn = document.createElement('button');
        btn.innerText = targetVal;
        btn.style.width = '100%';
        btn.onclick = () => switchTarget(targetVal);
        document.getElementById('target-list').appendChild(btn);
        
        // If it starts with #, automatically join the XMPP MUC room
        if (targetVal.startsWith('#')) {
            const roomName = targetVal.substring(1);
            xmppClient.joinGroup(roomName, myUsername);
        }
    }
    
    switchTarget(targetVal);
    document.getElementById('new-target').value = '';
});

function switchTarget(target) {
    activeTarget = target;
    const box = document.getElementById('chat-box');
    box.innerHTML = `<div style="color: #33ff00; border-bottom: 1px dashed #33ff00; margin-bottom: 10px;">--- Chatting with ${target} ---</div>`;
    
    if (chatHistory[target]) {
        chatHistory[target].forEach(msg => appendMessageToBox(msg.author, msg.text));
    }
}

// --- 4. SENDING MESSAGES ---
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

        // Render our own message instantly
        saveAndRenderMessage(activeTarget, myUsername, text);
        e.target.value = '';
    }
});

// --- 5. UI UTILITIES ---
function saveAndRenderMessage(target, author, text) {
    if (!chatHistory[target]) chatHistory[target] = [];
    chatHistory[target].push({ author, text });

    // Only draw it if we are currently looking at this target's tab
    if (activeTarget === target) {
        appendMessageToBox(author, text);
    }
}

function appendMessageToBox(author, text) {
    const box = document.getElementById('chat-box');
    const isMe = author === myUsername;
    const color = isMe ? '#00ffff' : '#ff00ff'; // Cyan for me, Magenta for them
    
    box.innerHTML += `<div style="margin-bottom: 5px;"><span style="color: ${color}">[${author}]</span> ${text}</div>`;
    box.scrollTop = box.scrollHeight; // Auto-scroll to bottom
}
