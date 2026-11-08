# Bazin Chat

Minimalist, zero-knowledge, cross-platform encrypted chat ecosystem over XMPP WebSockets (RFC 7395). Built with a terminal aesthetic, zero external CDNs, and pure-JS/Python RFC 8439 ChaCha20-Poly1305 encryption.

## Architecture & Security
- **Transport:** XMPP over WebSockets (\`wss://\`) with mandatory \`"xmpp"\` subprotocol
- **Backend:** Prosody XMPP bound strictly to loopback (\`127.0.0.1:5280\`) or internal container bridge
- **Crypto:** Native RFC 8439 ChaCha20-Poly1305 + PBKDF2-SHA256 (200,000 iterations)
- **Hardening:** Nonce replay protection, XML stanza injection escaping, strict CSP headers
- **Capabilities:** 1-on-1 direct messaging, Multi-User Chat (MUC) group rooms, multi-tab target routing, live in-memory key rotation

## Repository Structure
\`\`\`text
bazin-chat/
├── docker-compose.yml           # Containerized stack orchestration
├── web-client/                  # Zero-dependency Web Terminal (HTML/CSS/JS)
├── cli-client/                  # Python Terminal Client (txmpp.py)
└── infra/
    ├── playbook.yml             # Ansible automated bare-metal deployment
    ├── nginx.conf.template      # Hardened Reverse Proxy + CSP config
    └── prosody.cfg.lua.template # Hardened XMPP + MUC WebSocket config
\`\`\`

## Deployment Options

### Option A: Docker Compose
1. Replace \`chat.example.com\` in \`web-client/app.js\` and \`infra/*\` with your domain.
2. Launch the stack:
   \`\`\`bash
   docker compose up -d
   \`\`\`
3. Create an XMPP user:
   \`\`\`bash
   docker exec -it bazin-prosody prosodyctl adduser alice@chat.example.com
   \`\`\`

### Option B: Bare-Metal via Ansible (\`playbook.yml\`)
Deploy directly to a fresh Debian/Ubuntu VPS from your local machine:
\`\`\`bash
ansible-playbook -i "your_server_ip," -u root infra/playbook.yml --extra-vars "domain=chat.yourdomain.com"
\`\`\`
