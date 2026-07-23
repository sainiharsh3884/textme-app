'use strict';
/**
 * Textme chat server
 * - HTTP: static frontend + /api/signup, /api/login (JWT-based auth)
 * - WebSocket (/ws): real-time messaging, presence, disappearing-message timers,
 *   and WebRTC call signaling relay (offer/answer/ICE), all in-memory only.
 *
 * No message content is ever written to disk. Only account records
 * (username + password hash) persist, in server/users.json.
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.warn('[WARN] JWT_SECRET is not set — using an insecure generated dev secret. Set JWT_SECRET as an env var before deploying for real.');
}
const SECRET = JWT_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
const USERS_FILE = path.join(__dirname, 'users.json');
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const MAX_WS_PAYLOAD = 8 * 1024 * 1024; // 8MB per websocket frame (covers ~5MB media as base64)
const EMPTY_ROOM_SWEEP_MS = 5 * 60 * 1000;

// ---------------------------------------------------------------------------
// Password hashing (scrypt, built into Node — no extra deps)
// ---------------------------------------------------------------------------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  try {
    const [salt, hash] = stored.split(':');
    const hashBuf = Buffer.from(hash, 'hex');
    const testBuf = crypto.scryptSync(password, salt, 64);
    if (hashBuf.length !== testBuf.length) return false;
    return crypto.timingSafeEqual(hashBuf, testBuf);
  } catch (e) { return false; }
}

// ---------------------------------------------------------------------------
// Minimal JWT (HS256) — avoids pulling in a dependency for something this small
// ---------------------------------------------------------------------------
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function signToken(payload) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const now = Math.floor(Date.now() / 1000);
  const body = b64url(JSON.stringify(Object.assign({}, payload, { iat: now, exp: now + TOKEN_TTL_SECONDS })));
  const sig = b64url(crypto.createHmac('sha256', SECRET).update(`${header}.${body}`).digest());
  return `${header}.${body}.${sig}`;
}
function verifyToken(token) {
  try {
    const [header, body, sig] = String(token).split('.');
    if (!header || !body || !sig) return null;
    const expected = b64url(crypto.createHmac('sha256', SECRET).update(`${header}.${body}`).digest());
    if (sig.length !== expected.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64').toString('utf8'));
    if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) return null;
    return payload;
  } catch (e) { return null; }
}

// ---------------------------------------------------------------------------
// User store (account metadata only — never message content)
// ---------------------------------------------------------------------------
let users = {};
function loadUsers() {
  try { users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch (e) { users = {}; }
}
function saveUsers() {
  try { fs.writeFileSync(USERS_FILE, JSON.stringify(users)); }
  catch (e) { console.error('Failed to persist users.json:', e.message); }
}
loadUsers();

function validUsername(u) { return typeof u === 'string' && /^[a-zA-Z0-9_-]{3,20}$/.test(u); }

// naive per-IP rate limiting for auth endpoints
const authAttempts = new Map(); // ip -> { count, resetAt }
function rateLimited(ip) {
  const now = Date.now();
  let entry = authAttempts.get(ip);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + 60_000 };
    authAttempts.set(ip, entry);
  }
  entry.count++;
  return entry.count > 20; // 20 attempts/minute/IP
}

// ---------------------------------------------------------------------------
// HTTP: static file serving + auth API
// ---------------------------------------------------------------------------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function readBody(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) { reject(new Error('body too large')); req.destroy(); return; }
      data += chunk;
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

function serveStatic(req, res, urlPath) {
  let filePath = path.join(PUBLIC_DIR, urlPath === '/' ? 'index.html' : urlPath);
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); res.end('Forbidden'); return; }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      // SPA-style fallback to index.html for unknown paths
      fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (err2, data2) => {
        if (err2) { res.writeHead(404); res.end('Not found'); return; }
        res.writeHead(200, { 'Content-Type': MIME['.html'] });
        res.end(data2);
      });
      return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const url = new URL(req.url, `http://${req.headers.host}`);

  try {
    if (req.method === 'POST' && url.pathname === '/api/signup') {
      if (rateLimited(ip)) return sendJson(res, 429, { error: 'Too many attempts, slow down.' });
      const raw = await readBody(req);
      const { username, password } = JSON.parse(raw || '{}');
      if (!validUsername(username)) return sendJson(res, 400, { error: 'Username must be 3-20 chars: letters, numbers, _ or -' });
      if (typeof password !== 'string' || password.length < 6) return sendJson(res, 400, { error: 'Password must be at least 6 characters' });
      const key = username.toLowerCase();
      if (users[key]) return sendJson(res, 409, { error: 'That username is taken' });
      users[key] = { username, passwordHash: hashPassword(password), createdAt: Date.now() };
      saveUsers();
      return sendJson(res, 200, { token: signToken({ sub: username }) });
    }

    if (req.method === 'POST' && url.pathname === '/api/login') {
      if (rateLimited(ip)) return sendJson(res, 429, { error: 'Too many attempts, slow down.' });
      const raw = await readBody(req);
      const { username, password } = JSON.parse(raw || '{}');
      const key = String(username || '').toLowerCase();
      const record = users[key];
      if (!record || !verifyPassword(password || '', record.passwordHash)) {
        return sendJson(res, 401, { error: 'Invalid username or password' });
      }
      return sendJson(res, 200, { token: signToken({ sub: record.username }) });
    }

    if (req.method === 'GET' && url.pathname === '/api/me') {
      const auth = req.headers.authorization || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
      const payload = token && verifyToken(token);
      if (!payload) return sendJson(res, 401, { error: 'Invalid or expired token' });
      return sendJson(res, 200, { username: payload.sub });
    }

    if (req.method === 'GET' && url.pathname === '/api/users/search') {
      const auth = req.headers.authorization || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
      const payload = token && verifyToken(token);
      if (!payload) return sendJson(res, 401, { error: 'Invalid or expired token' });
      const q = String(url.searchParams.get('q') || '').trim().toLowerCase();
      if (!q) return sendJson(res, 200, { users: [] });
      if (q.length > 20) return sendJson(res, 200, { users: [] });
      const requester = payload.sub.toLowerCase();
      const USER_SEARCH_LIMIT = 10;
      const matches = [];
      for (const key of Object.keys(users)) {
        if (key === requester) continue;
        if (key.includes(q)) matches.push(users[key].username);
        if (matches.length >= USER_SEARCH_LIMIT) break;
      }
      return sendJson(res, 200, { users: matches });
    }

    if (req.method === 'GET' && url.pathname === '/api/health') {
      return sendJson(res, 200, { ok: true, rooms: rooms.size });
    }

    if (req.method === 'GET') {
      return serveStatic(req, res, url.pathname);
    }

    res.writeHead(404); res.end('Not found');
  } catch (e) {
    console.error('HTTP handler error:', e);
    sendJson(res, 500, { error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// In-memory room state (nothing here is ever persisted to disk)
// ---------------------------------------------------------------------------
/**
 * rooms: Map<roomCode, {
 *   timerSeconds: number,
 *   clients: Map<username, ws>,
 *   messages: Map<id, { sender, type, payload, createdAt, readBy: Map<username, ts>, deleteTimer }>
 * }>
 */
const rooms = new Map();

function getRoom(code) {
  if (!rooms.has(code)) {
    rooms.set(code, { timerSeconds: 300, clients: new Map(), messages: new Map() });
  }
  return rooms.get(code);
}

function send(ws, obj) {
  if (ws && ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
}
function broadcast(room, obj, exceptUsername) {
  for (const [uname, ws] of room.clients) {
    if (uname === exceptUsername) continue;
    send(ws, obj);
  }
}
function presenceList(room) {
  return Array.from(room.clients.keys());
}
function broadcastPresence(roomCode, room) {
  broadcast(room, { type: 'presence', users: presenceList(room) }, null);
}

function scheduleDeleteIfNeeded(roomCode, room, id) {
  const msg = room.messages.get(id);
  if (!msg || !room.timerSeconds || msg.deleteTimer) return;
  const readTimes = Array.from(msg.readBy.values());
  if (!readTimes.length) return;
  const firstRead = Math.min(...readTimes);
  const deleteAt = firstRead + room.timerSeconds * 1000;
  const delay = Math.max(0, deleteAt - Date.now());
  msg.deleteTimer = setTimeout(() => {
    room.messages.delete(id);
    broadcast(room, { type: 'message-deleted', id }, null);
  }, delay);
}

// sweep empty, message-less rooms periodically to free memory
setInterval(() => {
  for (const [code, room] of rooms) {
    if (room.clients.size === 0 && room.messages.size === 0) rooms.delete(code);
  }
}, EMPTY_ROOM_SWEEP_MS);

// ---------------------------------------------------------------------------
// WebSocket server
// ---------------------------------------------------------------------------
const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_WS_PAYLOAD });

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname !== '/ws') { socket.destroy(); return; }
  const token = url.searchParams.get('token');
  const roomCode = (url.searchParams.get('room') || '').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 60);
  const payload = token && verifyToken(token);
  if (!payload || !roomCode) { socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.username = payload.sub;
    ws.roomCode = roomCode;
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', (ws) => {
  const roomCode = ws.roomCode;
  const username = ws.username;
  const room = getRoom(roomCode);

  // if this user already has a connection open (e.g. reconnect), close the old one
  const existing = room.clients.get(username);
  if (existing && existing !== ws) { try { existing.close(); } catch (e) {} }
  room.clients.set(username, ws);
  ws.isAlive = true;

  // send initial state: current live (unburned) messages + settings + presence
  const liveMessages = Array.from(room.messages.entries()).map(([id, m]) => ({
    id, sender: m.sender, type: m.type, payload: m.payload, createdAt: m.createdAt,
    readBy: Object.fromEntries(m.readBy),
  }));
  send(ws, { type: 'joined', room: roomCode, timerSeconds: room.timerSeconds, presence: presenceList(room), messages: liveMessages });
  broadcastPresence(roomCode, room);

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }
    if (!msg || typeof msg.type !== 'string') return;

    switch (msg.type) {
      case 'message': {
        const id = Date.now().toString(36) + '-' + crypto.randomBytes(5).toString('hex');
        const record = { sender: username, type: msg.msgType, payload: msg.payload || {}, createdAt: Date.now(), readBy: new Map() };
        room.messages.set(id, record);
        broadcast(room, { type: 'message', id, sender: username, msgType: record.type, payload: record.payload, createdAt: record.createdAt }, null);
        break;
      }
      case 'read': {
        const m = room.messages.get(msg.id);
        if (!m || m.sender === username) break;
        if (!m.readBy.has(username)) {
          m.readBy.set(username, Date.now());
          broadcast(room, { type: 'read-receipt', id: msg.id, reader: username, readAt: m.readBy.get(username) }, null);
          scheduleDeleteIfNeeded(roomCode, room, msg.id);
        }
        break;
      }
      case 'settings': {
        const secs = Math.max(0, Math.min(7 * 24 * 3600, parseInt(msg.timerSeconds, 10) || 0));
        room.timerSeconds = secs;
        broadcast(room, { type: 'settings', timerSeconds: secs, changedBy: username }, null);
        break;
      }
      case 'call-offer': {
        broadcast(room, { type: 'incoming-call', callId: msg.callId, from: username, callType: msg.callType, sdp: msg.sdp }, username);
        break;
      }
      case 'call-answer': {
        send(room.clients.get(msg.to), { type: 'call-answer', callId: msg.callId, from: username, sdp: msg.sdp });
        break;
      }
      case 'call-ice': {
        send(room.clients.get(msg.to), { type: 'call-ice', callId: msg.callId, from: username, candidate: msg.candidate });
        break;
      }
      case 'call-end': {
        if (msg.to) send(room.clients.get(msg.to), { type: 'call-ended', callId: msg.callId, from: username });
        else broadcast(room, { type: 'call-ended', callId: msg.callId, from: username }, username);
        break;
      }
      case 'screenshot-alert': {
        broadcast(room, { type: 'screenshot-alert', by: username }, username);
        break;
      }
      default: break;
    }
  });

  ws.on('close', () => {
    if (room.clients.get(username) === ws) {
      room.clients.delete(username);
      broadcastPresence(roomCode, room);
    }
  });

  ws.on('error', () => {});
});

// heartbeat to drop dead connections
const heartbeat = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30_000);

server.on('close', () => clearInterval(heartbeat));

server.listen(PORT, () => {
  console.log(`Textme server listening on port ${PORT}`);
  if (!JWT_SECRET) console.warn('Reminder: set a real JWT_SECRET env var in production.');
});
