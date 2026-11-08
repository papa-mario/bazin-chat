#!/usr/bin/env python3
import asyncio
import base64
import getpass
import os
import sys
import xml.etree.ElementTree as ET
import websockets
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

WS_URL = "wss://chat.example.com/xmpp-websocket"
DOMAIN = "chat.example.com"
SALT = b"bazin-chat-open-source-salt-key"

def derive_key(passphrase: str) -> bytes:
    """Derives a 256-bit symmetric key from a shared room/peer passphrase."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=200_000,
    )
    return kdf.derive(passphrase.encode("utf-8"))

def encrypt_msg(key: bytes, plaintext: str) -> str:
    """Encrypts plaintext using ChaCha20-Poly1305 (96-bit random nonce)."""
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, plaintext.encode("utf-8"), None)
    return "E2EE:" + base64.b64encode(nonce + ct).decode("ascii")

def decrypt_msg(key: bytes, payload: str) -> str:
    """Decrypts an E2EE: base64 payload."""
    if not payload.startswith("E2EE:"):
        return f"[UNENCRYPTED] {payload}"
    try:
        raw = base64.b64decode(payload[5:])
        nonce, ct = raw[:12], raw[12:]
        aead = ChaCha20Poly1305(key)
        return aead.decrypt(nonce, ct, None).decode("utf-8")
    except Exception:
        return "[DECRYPTION FAILED - Wrong E2EE Key]"

class MinimalXMPPClient:
    def __init__(self, jid: str, password: str, e2ee_key: bytes):
        self.jid = jid
        self.user = jid.split("@")[0]
        self.password = password
        self.e2ee_key = e2ee_key
        self.active_peer = None
        self.ws = None

    async def send_xml(self, xml_str: str):
        await self.ws.send(xml_str)

    async def authenticate_and_bind(self):
        # 1. Open RFC 7395 WebSocket XMPP Stream
        await self.send_xml(
            f'<open xmlns="urn:ietf:params:xml:ns:xmpp-framing" to="{DOMAIN}" version="1.0"/>'
        )
        # Wait for server <open> and <stream:features>
        for _ in range(2):
            await self.ws.recv()

        # 2. SASL PLAIN Authentication (Protected by outer TLS 1.3 on port 443)
        auth_str = f"\0{self.user}\0{self.password}".encode("utf-8")
        b64_auth = base64.b64encode(auth_str).decode("ascii")
        await self.send_xml(
            f'<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="PLAIN">{b64_auth}</auth>'
        )
        auth_resp = await self.ws.recv()
        if "success" not in auth_resp:
            print("\nACH KATKHRB9 3awd dakchi")
            sys.exit(1)

        # 3. Re-open stream after SASL success
        await self.send_xml(
            f'<open xmlns="urn:ietf:params:xml:ns:xmpp-framing" to="{DOMAIN}" version="1.0"/>'
        )
        for _ in range(2):
            await self.ws.recv()

        # 4. Bind ephemeral resource
        await self.send_xml(
            '<iq type="set" id="bind_1" xmlns="jabber:client">'
            '<bind xmlns="urn:ietf:params:xml:ns:xmpp-bind">'
            '<resource>terminal</resource>'
            '</bind></iq>'
        )
        await self.ws.recv()

        # 5. Announce in-memory presence
        await self.send_xml('<presence xmlns="jabber:client"/>')
        print(f"\nRak 3la lkhat")
        print("Commands: /to <user@chat.example.com> | /key <new_secret> | /quit\n")

    async def receive_loop(self):
        try:
            async for frame in self.ws:
                if "<message" in frame and "<body" in frame:
                    root = ET.fromstring(frame)
                    sender = root.attrib.get("from", "unknown").split("/")[0]
                    body_el = root.find("{jabber:client}body")
                    if body_el is not None and body_el.text:
                        decrypted = decrypt_msg(self.e2ee_key, body_el.text)
                        sys.stdout.write(f"\r\033[K[{sender}] > {decrypted}\n> ")
                        sys.stdout.flush()
                elif "<ping" in frame:
                    root = ET.fromstring(frame)
                    ping_id = root.attrib.get("id", "1")
                    await self.send_xml(f'<iq type="result" to="{DOMAIN}" id="{ping_id}" xmlns="jabber:client"/>')
        except websockets.ConnectionClosed:
            print("\nALLO TISSALAT")
            os._exit(0)

    async def input_loop(self):
        loop = asyncio.get_running_loop()
        while True:
            line = await loop.run_in_executor(None, lambda: input("> "))
            line = line.strip()
            if not line:
                continue
            if line == "/quit":
                await self.send_xml('<close xmlns="urn:ietf:params:xml:ns:xmpp-framing"/>')
                break
            elif line.startswith("/to "):
                target = line.split(" ", 1)[1].strip()
                if "@" not in target:
                    target = f"{target}@{DOMAIN}"
                self.active_peer = target
                print(f"You are talking to {self.active_peer}")
            elif line.startswith("/key "):
                new_secret = line.split(" ", 1)[1].strip()
                self.e2ee_key = derive_key(new_secret)
                print("E2EE updated ola man3rf anbdel mazal hadchi")
            else:
                if not self.active_peer:
                    print("kteb /to +smia dial li bithder m3ah")
                    continue
                ciphertext = encrypt_msg(self.e2ee_key, line)
                stanza = (
                    f'<message to="{self.active_peer}" type="chat" xmlns="jabber:client">'
                    f"<body>{ciphertext}</body>"
                    f"</message>"
                )
                await self.send_xml(stanza)

    async def run(self):
        async with websockets.connect(
            WS_URL,
            subprotocols=["xmpp"],
            ping_interval=30,
            ping_timeout=10,
        ) as ws:
            self.ws = ws
            await self.authenticate_and_bind()
            await asyncio.gather(self.receive_loop(), self.input_loop())

if __name__ == "__main__":
    print("=== Khasskom BZAAF ===")
    jid_in = input("SMIA: ").strip()
    if "@" not in jid_in:
        jid_in = f"{jid_in}@{DOMAIN}"
    pw_in = getpass.getpass("Password: ")
    secret_in = getpass.getpass("passkey bach maychofkch mol server: ")
    client = MinimalXMPPClient(jid_in, pw_in, derive_key(secret_in))
    try:
        asyncio.run(client.run())
    except KeyboardInterrupt:
        print("\nAdios")
