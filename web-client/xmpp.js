// xmpp.js
export class BazinXMPP {
    constructor(domain, username, password, onReady, onError) {
        this.domain = domain;
        this.jid = `${username}@${domain}`;
        
        const wsHost = window.location.hostname;
        this.ws = new WebSocket(`wss://${wsHost}/xmpp-websocket`, 'xmpp');
        
        this.onMessageReceived = null;
        this.isAuthenticated = false;
        this.pendingQueue = [];
        this.pingInterval = null;

        this.ws.onopen = () => {
            console.log("[XMPP] WebSocket Connected. Opening stream...");
            this.ws.send(`<open to="${this.domain}" version="1.0" xmlns="urn:ietf:params:xml:ns:xmpp-framing"/>`);
            
            // Send a blank space every 30 seconds to prevent Nginx/Prosody from dropping idle connections
            this.pingInterval = setInterval(() => {
                if (this.ws.readyState === WebSocket.OPEN) this.ws.send(' ');
            }, 30000);
        };

        this.ws.onmessage = (event) => {
            const xml = event.data;
            if (xml.trim() !== '') console.log("[XMPP IN]", xml);

            if (!this.isAuthenticated) {
                if (/<failure[\s/>]/.test(xml) || (/<stream:error[\s/>]/.test(xml) && !xml.includes('host-unknown'))) {
                    console.error("[XMPP] Authentication/Stream Failure:", xml);
                    if (onError) onError("Authentication failed.");
                    this.ws.close();
                    return;
                }

                if (/<mechanisms[\s>]/.test(xml)) {
                    const authStr = btoa(`\x00${username}\x00${password}`);
                    this.ws.send(`<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="PLAIN">${authStr}</auth>`);
                } 
                else if (/<success[\s/>]/.test(xml)) {
                    this.ws.send(`<open to="${this.domain}" version="1.0" xmlns="urn:ietf:params:xml:ns:xmpp-framing"/>`);
                } 
                else if (/<stream:features[\s>]/.test(xml)) {
                    if (/<bind[\s/>]/.test(xml)) {
                        this.ws.send(`<iq type="set" id="bind1" xmlns="jabber:client"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"><resource>web</resource></bind></iq>`);
                    }
                } 
                else if (/id=['"]bind1['"]/.test(xml) && /type=['"]result['"]/.test(xml)) {
                    this.ws.send(`<presence xmlns="jabber:client"/>`);
                    this.isAuthenticated = true;
                    console.log("[XMPP] Authenticated and Ready!");

                    while (this.pendingQueue.length > 0) {
                        this.ws.send(this.pendingQueue.shift());
                    }
                    if (onReady) onReady();
                }
                return;
            }

            if (this.onMessageReceived && /<message[\s>]/.test(xml)) {
                this.onMessageReceived(xml);
            }
        };

        this.ws.onerror = (err) => {
            console.error("[XMPP] WebSocket Error:", err);
            if (!this.isAuthenticated && onError) onError("WebSocket connection error.");
        };

        this.ws.onclose = () => {
            console.warn("[XMPP] WebSocket Closed.");
            if (this.pingInterval) clearInterval(this.pingInterval);
        };
    }

    sendRaw(stanza) {
        if (this.isAuthenticated && this.ws.readyState === WebSocket.OPEN) {
            console.log("[XMPP OUT]", stanza);
            this.ws.send(stanza);
        } else {
            this.pendingQueue.push(stanza);
        }
    }

    sendDirectMessage(to, ciphertext) {
        const stanza = `<message to="${to}" type="chat" xmlns="jabber:client"><body>${ciphertext}</body></message>`;
        this.sendRaw(stanza);
    }

    joinGroup(roomName, nick) {
        const roomJid = `${roomName}@conference.${this.domain}/${nick}`;
        const stanza = `<presence to="${roomJid}" xmlns="jabber:client"><x xmlns="http://jabber.org/protocol/muc"/></presence>`;
        this.sendRaw(stanza);
    }

    sendGroupMessage(roomName, ciphertext) {
        const roomJid = `${roomName}@conference.${this.domain}`;
        const stanza = `<message to="${roomJid}" type="groupchat" xmlns="jabber:client"><body>${ciphertext}</body></message>`;
        this.sendRaw(stanza);
    }
}
