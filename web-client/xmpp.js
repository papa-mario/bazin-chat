// xmpp.js
export class BazinXMPP {
    constructor(domain, username, password) {
        this.domain = domain;
        this.jid = `${username}@${domain}`;
        this.ws = new WebSocket(`wss://${domain}/xmpp-websocket`, 'xmpp');
        
        this.onMessageReceived = null; // We will set this in app.js

        // Listen for incoming WebSocket messages
        this.ws.onmessage = (event) => {
            if (this.onMessageReceived) {
                this.onMessageReceived(event.data);
            }
        };
    }

    sendDirectMessage(to, ciphertext) {
        const stanza = `<message to="${to}" type="chat"><body>${ciphertext}</body></message>`;
        this.ws.send(stanza);
    }

    joinGroup(roomName, nick) {
        const roomJid = `${roomName}@conference.${this.domain}/${nick}`;
        // Sending presence to a room JID joins the room
        const stanza = `
            <presence to="${roomJid}">
                <x xmlns="http://jabber.org/protocol/muc"/>
            </presence>`;
        this.ws.send(stanza);
    }

    sendGroupMessage(roomName, ciphertext) {
        const roomJid = `${roomName}@conference.${this.domain}`;
        const stanza = `
            <message to="${roomJid}" type="groupchat">
                <body>${ciphertext}</body>
            </message>`;
        this.ws.send(stanza);
    }
}
