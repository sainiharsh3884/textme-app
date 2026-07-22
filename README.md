# Textme — disappearing-message chat for you and your friends

A real-time chat app with voice/video calling and messages that auto-delete a set
time after being read. Self-contained Node.js backend, no external database required.

## What's actually running here

- **Auth**: real accounts (username + password), JWT tokens, passwords hashed with scrypt.
- **Messaging**: WebSocket, in-memory only — nothing is written to disk except account
  records (username + password hash). Message content, read receipts, and media never
  touch the disk or leave the server process's memory.
- **Auto-delete**: each room has a configurable timer (30s / 5min / 1hr / 1day / off).
  The countdown starts when a message is first read, and the server itself deletes it
  and broadcasts the deletion to everyone in the room — deletion isn't just a client-side
  trick, it's enforced server-side even if a client is misbehaving.
- **Calling**: real WebRTC, peer-to-peer. The server only relays the signaling handshake
  (offer/answer/ICE candidates) — actual audio/video never passes through the server.
- **Screenshot deterrence**: best-effort only (see note below) — this is a genuine
  limitation of what a browser allows, not something specific to this app.

## Before you deploy: two things to know

1. **No TURN server is configured** — only public STUN servers. This means calls work
   great on most home/wifi connections, but may fail to connect on strict corporate
   networks or some mobile carriers (roughly 15–20% of real-world connections need a TURN
   relay to succeed). If that becomes a problem, the fix is to run your own `coturn`
   server (or use a managed TURN provider) and add it to the `STUN` config in
   `public/index.html`.
2. **Screenshots cannot be truly blocked in a browser.** The app detects likely
   screenshot attempts (PrintScreen key, window losing focus, print dialogs) and notifies
   the other person, and blurs content during the moment of suspected capture — the same
   approach Telegram/Signal use for this on the web. It cannot stop someone photographing
   their screen with another device.

## Running it locally

```bash
cd server
npm install
JWT_SECRET="pick-a-long-random-string-here" npm start
```

Then open `http://localhost:8080` in your browser. Sign up, then have a friend sign up
from their own browser and enter the same room code as you.

## Deploying so your friends can actually reach it

Any host that runs Node.js works. Two easy free-tier options:

### Option A: Render.com (simplest)
1. Push this project to a GitHub repo.
2. On Render: **New → Web Service**, connect the repo, set:
   - Root directory: `server`
   - Build command: `npm install`
   - Start command: `npm start`
   - Environment variable: `JWT_SECRET` = (generate a long random string)
3. Render serves the frontend automatically too, since `server.js` serves
   everything in `../public` as static files — no separate frontend deploy needed.
4. Once deployed you'll get a URL like `https://your-app.onrender.com` — share that
   with friends along with a room code.

### Option B: Fly.io / Railway / a plain VPS
Same idea — install Node 18+, `npm install` inside `server/`, set `JWT_SECRET`,
run `npm start` (or use a process manager like `pm2` on a VPS so it survives reboots),
and make sure port 8080 (or your chosen `PORT` env var) is reachable over HTTPS.
**HTTPS matters** — camera/microphone access (`getUserMedia`) is blocked by browsers
on plain HTTP for any host other than `localhost`. Render/Fly/Railway give you HTTPS
automatically; on a raw VPS you'll want a reverse proxy (Caddy is the easiest — it
gets you free auto-renewing HTTPS with about 3 lines of config) in front of the Node app.

## Generating a good JWT_SECRET

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```
Paste the output as the `JWT_SECRET` environment variable wherever you deploy.
Never commit it to your repo.

## Project layout

```
textme-app/
├── server/
│   ├── server.js       # HTTP auth API + WebSocket chat/call server
│   ├── package.json
│   └── test/            # integration test (optional, dev use only)
│       ├── mini-ws-client.js
│       └── integration.js
├── public/
│   └── index.html        # the whole frontend (single file)
└── README.md
```

## Verifying your deployment works (optional)

`server/test/integration.js` drives the real server through: signup, room join,
presence, a message send + read + auto-delete cycle, and full call-signaling relay
(offer/answer/ICE/end). To run it against a local instance:

```bash
cd server
npm install
JWT_SECRET=testsecret npm start &
node test/integration.js
```
All checks should print `PASS`.

## Known limitations / where this differs from the full production plan

This is built to be genuinely usable by a small friend group, not a hardened,
audited product. Compared to the fuller architecture discussed earlier in this
project (Signal Protocol E2EE, Redis-backed clustering, TURN infra, S3 media storage):

- No end-to-end encryption of message content yet — the server can technically read
  messages in transit (though it never writes them to disk). Adding Signal Protocol
  (libsignal) on top of this is the natural next step if that matters to you.
- Single server process, in-memory state — fine for a friend group, won't horizontally
  scale past one machine without adding Redis for shared state.
- Media (images/files) are capped at a few MB and held in server RAM only for as long
  as the message lives — there's no object storage layer.
- No TURN server, as noted above.

Happy to build any of these out further whenever you're ready.
