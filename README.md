# Bazin Chat

Minimalist, zero-knowledge, cross-platform encrypted chat ecosystem over raw XMPP WebSockets (RFC 7395). Built with a terminal aesthetic, featuring zero runtime CDN dependencies and pure-JS/Python RFC 8439 ChaCha20-Poly1305 encryption.

## Private & Local-First Communication
Bazin Chat is engineered to function out of the box as a fully self-hosted, private communications hub for you and your friends. By running the lightweight backend on a home server, a Raspberry Pi, or any local machine, you create an isolated chat environment completely independent of commercial messaging silos or third-party servers. Friends on the same local Wi-Fi, LAN, or private mesh network (such as Tailscale or WireGuard) can connect directly via their browser or terminal. Combined with end-to-end ChaCha20-Poly1305 encryption using pre-shared room secrets, your messages remain indecipherable even to the host machine routing the packets.

## Architecture & Security
- **Transport:** XMPP over WebSockets (`wss://`) with mandatory `"xmpp"` subprotocol
- **Backend:** Prosody XMPP bound strictly to loopback (`127.0.0.1:5280`) or internal container bridge
- **Crypto:** Native RFC 8439 ChaCha20-Poly1305 + PBKDF2-SHA256 (200,000 iterations)
- **Hardening:** Nonce replay protection, XML stanza injection escaping, strict CSP headers
- **Capabilities:** 1-on-1 direct messaging, Multi-User Chat (MUC) group rooms, multi-tab target routing, live in-memory key rotation

## Repository Structure
```text
bazin-chat/
├── docker-compose.yml           # Containerized stack orchestration
├── web-client/                  # Zero-dependency Web Terminal (HTML/CSS/JS)
├── cli-client/                  # Python Terminal Client (txmpp.py)
└── infra/
    ├── playbook.yml             # Ansible automated bare-metal deployment
    ├── nginx.conf.template      # Hardened Reverse Proxy + CSP config
    └── prosody.cfg.lua.template # Hardened XMPP + MUC WebSocket config
```

## Deployment Options

### Option A: Docker Compose (Recommended)
1. Replace `chat.example.com` in `web-client/app.js` and `infra/*` with your domain or LAN IP.
2. Launch the stack:
   ```bash
   docker compose up -d
   ```
3. Create an XMPP user:
   ```bash
   docker exec -it bazin-prosody prosodyctl adduser alice@chat.example.com
   ```

### Option B: Bare-Metal via Ansible (`playbook.yml`)
Deploy directly to a fresh Debian/Ubuntu server from your local machine:
```bash
ansible-playbook -i "your_server_ip," -u root infra/playbook.yml --extra-vars "domain=chat.yourdomain.com"
```

## Running the CLI Client
```bash
cd cli-client
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python txmpp.py
```
