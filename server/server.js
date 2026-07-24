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
//
// On Render, the local filesystem is wiped on every deploy/restart, so a
// plain users.json file loses every signed-up account each time you push.
// If a DATABASE_URL env var is present (attach a free Render Postgres to
// this service and it sets this automatically), accounts are stored there
// instead and survive deploys/restarts. Without DATABASE_URL, it falls
// back to the local users.json file, which is fine for local development.
// ---------------------------------------------------------------------------
const USE_DB = !!process.env.DATABASE_URL;
let pool = null;
let users = {}; // only used in file-mode: key(lowercase username) -> { username, passwordHash, createdAt }

if (USE_DB) {
  const { Pool } = require('pg');
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL) ? false : { rejectUnauthorized: false },
  });
} else {
  console.warn('[WARN] DATABASE_URL is not set — using local users.json file. On Render this will NOT persist across deploys/restarts. Attach a Render Postgres database to this service to fix that permanently.');
}

async function initUserStore() {
  if (USE_DB) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        username_key TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at BIGINT NOT NULL
      )
    `);
    console.log('[DB] Connected to Postgres — accounts will persist across deploys.');
  } else {
    loadUsersFromFile();
  }
}

function loadUsersFromFile() {
  try { users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch (e) { users = {}; }
}
function saveUsersToFile() {
  try { fs.writeFileSync(USERS_FILE, JSON.stringify(users)); }
  catch (e) { console.error('Failed to persist users.json:', e.message); }
}

// getUserByKey(usernameLowercase) -> { username, passwordHash, createdAt } | null
async function getUserByKey(key) {
  if (USE_DB) {
    const { rows } = await pool.query(
      'SELECT username, password_hash AS "passwordHash", created_at AS "createdAt" FROM users WHERE username_key = $1',
      [key]
    );
    return rows[0] || null;
  }
  return users[key] || null;
}

async function createUser(username, passwordHash) {
  const key = username.toLowerCase();
  if (USE_DB) {
    await pool.query(
      'INSERT INTO users (username_key, username, password_hash, created_at) VALUES ($1,$2,$3,$4)',
      [key, username, passwordHash, Date.now()]
    );
  } else {
    users[key] = { username, passwordHash, createdAt: Date.now() };
    saveUsersToFile();
  }
}

// searchUsernames(query, excludeKey, limit) -> string[] of matching usernames
async function searchUsernames(query, excludeKey, limit) {
  if (USE_DB) {
    const { rows } = await pool.query(
      'SELECT username FROM users WHERE username_key LIKE $1 AND username_key != $2 ORDER BY username_key LIMIT $3',
      [`%${query}%`, excludeKey, limit]
    );
    return rows.map(r => r.username);
  }
  const matches = [];
  for (const key of Object.keys(users)) {
    if (key === excludeKey) continue;
    if (key.includes(query)) matches.push(users[key].username);
    if (matches.length >= limit) break;
  }
  return matches;
}

function validUsername(u) { return typeof u === 'string' && /^[a-zA-Z0-9_-]{3,20}$/.test(u); }

// ---------------------------------------------------------------------------
// Channel store (permanent public rooms, like a Telegram channel).
// Only metadata persists (code/name/description/creator/members) — never
// message content, same privacy rule as the rest of this file. Uses the same
// DB-if-available / file-fallback pattern as the user store above.
// ---------------------------------------------------------------------------
const CHANNELS_FILE = path.join(__dirname, 'channels.json');
let channels = {}; // file-mode only: code -> { code, name, description, createdBy, createdAt, members: {usernameKey: username} }

async function initChannelStore() {
  if (USE_DB) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS channels (
        code TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        created_by TEXT NOT NULL,
        created_at BIGINT NOT NULL
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS channel_members (
        code TEXT NOT NULL,
        username_key TEXT NOT NULL,
        username TEXT NOT NULL,
        joined_at BIGINT NOT NULL,
        PRIMARY KEY (code, username_key)
      )
    `);
  } else {
    try { channels = JSON.parse(fs.readFileSync(CHANNELS_FILE, 'utf8')); } catch (e) { channels = {}; }
  }
}
function saveChannelsToFile() {
  try { fs.writeFileSync(CHANNELS_FILE, JSON.stringify(channels)); }
  catch (e) { console.error('Failed to persist channels.json:', e.message); }
}
function validChannelName(n) { return typeof n === 'string' && n.trim().length >= 3 && n.trim().length <= 40; }
function slug(s) { return String(s || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60); }

async function getChannel(code) {
  if (USE_DB) {
    const { rows } = await pool.query(
      'SELECT code, name, description, created_by AS "createdBy", created_at AS "createdAt" FROM channels WHERE code = $1',
      [code]
    );
    if (!rows[0]) return null;
    const { rows: mrows } = await pool.query('SELECT COUNT(*)::int AS count FROM channel_members WHERE code = $1', [code]);
    return Object.assign({}, rows[0], { memberCount: mrows[0].count });
  }
  const c = channels[code];
  if (!c) return null;
  return { code: c.code, name: c.name, description: c.description, createdBy: c.createdBy, createdAt: c.createdAt, memberCount: Object.keys(c.members).length };
}

async function createChannel(name, description, createdBy) {
  const base = slug(name).slice(0, 30) || 'channel';
  let code;
  do { code = `ch-${base}-${crypto.randomBytes(3).toString('hex')}`; } while (await getChannel(code));
  const createdAt = Date.now();
  const desc = (description || '').slice(0, 200);
  if (USE_DB) {
    await pool.query('INSERT INTO channels (code, name, description, created_by, created_at) VALUES ($1,$2,$3,$4,$5)', [code, name, desc, createdBy, createdAt]);
    await pool.query(
      'INSERT INTO channel_members (code, username_key, username, joined_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING',
      [code, createdBy.toLowerCase(), createdBy, createdAt]
    );
  } else {
    channels[code] = { code, name, description: desc, createdBy, createdAt, members: { [createdBy.toLowerCase()]: createdBy } };
    saveChannelsToFile();
  }
  return { code, name, description: desc, createdBy, createdAt, memberCount: 1 };
}

async function listChannels(limit = 100) {
  if (USE_DB) {
    const { rows } = await pool.query(`
      SELECT c.code, c.name, c.description, c.created_by AS "createdBy", c.created_at AS "createdAt",
             COUNT(m.username_key)::int AS "memberCount"
      FROM channels c LEFT JOIN channel_members m ON m.code = c.code
      GROUP BY c.code ORDER BY c.created_at DESC LIMIT $1
    `, [limit]);
    return rows;
  }
  return Object.values(channels)
    .sort((a, b) => b.createdAt - a.createdAt)
    .slice(0, limit)
    .map(c => ({ code: c.code, name: c.name, description: c.description, createdBy: c.createdBy, createdAt: c.createdAt, memberCount: Object.keys(c.members).length }));
}

async function joinChannel(code, username) {
  const key = username.toLowerCase();
  if (USE_DB) {
    await pool.query(
      'INSERT INTO channel_members (code, username_key, username, joined_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING',
      [code, key, username, Date.now()]
    );
    return true;
  }
  const c = channels[code];
  if (!c) return false;
  c.members[key] = username;
  saveChannelsToFile();
  return true;
}

async function getUserChannels(usernameKey) {
  if (USE_DB) {
    const { rows } = await pool.query(`
      SELECT c.code, c.name, c.description, c.created_by AS "createdBy", c.created_at AS "createdAt",
             (SELECT COUNT(*)::int FROM channel_members m2 WHERE m2.code = c.code) AS "memberCount"
      FROM channels c JOIN channel_members m ON m.code = c.code
      WHERE m.username_key = $1 ORDER BY c.created_at DESC
    `, [usernameKey]);
    return rows;
  }
  return Object.values(channels)
    .filter(c => usernameKey in c.members)
    .map(c => ({ code: c.code, name: c.name, description: c.description, createdBy: c.createdBy, createdAt: c.createdAt, memberCount: Object.keys(c.members).length }));
}

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
      if (await getUserByKey(key)) return sendJson(res, 409, { error: 'That username is taken' });
      await createUser(username, hashPassword(password));
      return sendJson(res, 200, { token: signToken({ sub: username }) });
    }

    if (req.method === 'POST' && url.pathname === '/api/login') {
      if (rateLimited(ip)) return sendJson(res, 429, { error: 'Too many attempts, slow down.' });
      const raw = await readBody(req);
      const { username, password } = JSON.parse(raw || '{}');
      const key = String(username || '').toLowerCase();
      const record = await getUserByKey(key);
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
      const matches = await searchUsernames(q, requester, USER_SEARCH_LIMIT);
      return sendJson(res, 200, { users: matches });
    }

    if (req.method === 'GET' && url.pathname === '/api/conversations') {
      const auth = req.headers.authorization || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
      const payload = token && verifyToken(token);
      if (!payload) return sendJson(res, 401, { error: 'Invalid or expired token' });
      return sendJson(res, 200, { conversations: buildConversationsList(payload.sub.toLowerCase()) });
    }

    if (req.method === 'POST' && url.pathname === '/api/channels') {
      const auth = req.headers.authorization || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
      const payload = token && verifyToken(token);
      if (!payload) return sendJson(res, 401, { error: 'Invalid or expired token' });
      const raw = await readBody(req);
      let body; try { body = JSON.parse(raw || '{}'); } catch (e) { body = {}; }
      const name = String(body.name || '').trim();
      if (!validChannelName(name)) return sendJson(res, 400, { error: 'Channel name must be 3-40 characters' });
      const description = String(body.description || '').trim();
      const channel = await createChannel(name, description, payload.sub);
      return sendJson(res, 200, { channel });
    }

    if (req.method === 'GET' && url.pathname === '/api/channels') {
      const auth = req.headers.authorization || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
      const payload = token && verifyToken(token);
      if (!payload) return sendJson(res, 401, { error: 'Invalid or expired token' });
      const list = await listChannels(100);
      return sendJson(res, 200, { channels: list });
    }

    if (req.method === 'POST' && /^\/api\/channels\/[^/]+\/join$/.test(url.pathname)) {
      const auth = req.headers.authorization || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
      const payload = token && verifyToken(token);
      if (!payload) return sendJson(res, 401, { error: 'Invalid or expired token' });
      const code = decodeURIComponent(url.pathname.split('/')[3]);
      const channel = await getChannel(code);
      if (!channel) return sendJson(res, 404, { error: 'Channel not found' });
      await joinChannel(code, payload.sub);
      return sendJson(res, 200, { ok: true, channel });
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

// 'ch-' rooms are permanent public channels — never swept even with no
// clients/messages. 'dm-' and everything else keep the original ephemeral
// behavior (swept once empty).
function getRoom(code) {
  if (!rooms.has(code)) {
    rooms.set(code, { timerSeconds: 300, clients: new Map(), messages: new Map(), permanent: code.startsWith('ch-') });
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

// ---------------------------------------------------------------------------
// Cross-room user connections — every open socket for a user, regardless of
// which room (or the room-less "lobby") it's attached to. This is what lets
// a DM reach someone even if they're not currently sitting inside that exact
// chat room, instead of requiring both people to manually open the same room
// code at the same time.
// ---------------------------------------------------------------------------
const userConnections = new Map(); // usernameKey -> Set<ws>
function addUserConnection(usernameKey, ws) {
  if (!userConnections.has(usernameKey)) userConnections.set(usernameKey, new Set());
  userConnections.get(usernameKey).add(ws);
}
function removeUserConnection(usernameKey, ws) {
  const set = userConnections.get(usernameKey);
  if (!set) return;
  set.delete(ws);
  if (set.size === 0) userConnections.delete(usernameKey);
}
function sendToUser(usernameKey, obj) {
  const set = userConnections.get(usernameKey);
  if (!set) return;
  for (const sock of set) send(sock, obj);
}

function dmRoomCode(userA, userB) {
  const pair = [userA.toLowerCase(), userB.toLowerCase()].sort();
  return slug(`dm-${pair[0]}-${pair[1]}`);
}
function previewFor(msgType, payload) {
  switch (msgType) {
    case 'image': return '📷 Photo';
    case 'file': return `📎 ${(payload && payload.fileName) || 'File'}`;
    case 'contact': return `👤 ${(payload && payload.contactName) || 'Contact'} shared`;
    default: {
      const t = (payload && payload.text) || '';
      return t.length > 60 ? t.slice(0, 60) + '…' : t;
    }
  }
}

// dm-<pair> metadata: who the two participants are, the last message preview
// (for a chat list, cleared once that message burns), and per-user unread
// counters — this is what powers "message arrives on their account", not
// just "message arrives if they happen to already be in that room".
const dmIndex = new Map(); // roomCode -> { participants: {key: username}, lastMessage: {...}|null, unread: {key: count} }
function getDmEntry(roomCode) {
  if (!dmIndex.has(roomCode)) dmIndex.set(roomCode, { participants: {}, lastMessage: null, unread: {} });
  return dmIndex.get(roomCode);
}
function registerDmParticipants(roomCode, userA, userB) {
  const entry = getDmEntry(roomCode);
  entry.participants[userA.toLowerCase()] = userA;
  entry.participants[userB.toLowerCase()] = userB;
}
function clearUnread(roomCode, usernameKey) {
  const entry = dmIndex.get(roomCode);
  if (entry) entry.unread[usernameKey] = 0;
}
function buildConversationsList(usernameKey) {
  const list = [];
  for (const [roomCode, entry] of dmIndex) {
    if (!(usernameKey in entry.participants)) continue;
    const otherKey = Object.keys(entry.participants).find(k => k !== usernameKey);
    if (!otherKey) continue;
    list.push({
      room: roomCode,
      otherUser: entry.participants[otherKey],
      lastMessage: entry.lastMessage,
      unread: entry.unread[usernameKey] || 0,
    });
  }
  list.sort((a, b) => (b.lastMessage ? b.lastMessage.createdAt : 0) - (a.lastMessage ? a.lastMessage.createdAt : 0));
  return list;
}
async function sendLobbyState(ws, username) {
  const usernameKey = username.toLowerCase();
  const [myChannels] = await Promise.all([getUserChannels(usernameKey)]);
  send(ws, { type: 'lobby-joined', conversations: buildConversationsList(usernameKey), channels: myChannels });
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
    if (roomCode.startsWith('dm-')) {
      const entry = dmIndex.get(roomCode);
      if (entry && entry.lastMessage && entry.lastMessage.id === id) entry.lastMessage = null;
    }
  }, delay);
}

// sweep empty, message-less rooms periodically to free memory
setInterval(() => {
  for (const [code, room] of rooms) {
    if (room.permanent) continue;
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
  const rawRoom = url.searchParams.get('room') || '';
  // '__lobby__' is a virtual, room-less connection kept open while the
  // account is logged in (landing page, browsing chats, etc.) purely so the
  // server has somewhere to push "you got a new DM" notifications, even when
  // the person isn't currently inside that specific chat room.
  const roomCode = rawRoom === '__lobby__' ? '__lobby__' : rawRoom.toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 60);
  const peerRaw = url.searchParams.get('peer');
  const peer = peerRaw && validUsername(peerRaw) ? peerRaw : null;
  const payload = token && verifyToken(token);
  if (!payload || !roomCode) { socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.username = payload.sub;
    ws.roomCode = roomCode;
    ws.peer = peer;
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', (ws) => {
  const username = ws.username;
  const usernameKey = username.toLowerCase();
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
  addUserConnection(usernameKey, ws);

  // Lobby connections don't belong to a chat room — they just sit open so
  // the server can push notifications, and get the current chat/channel
  // list on connect.
  if (ws.roomCode === '__lobby__') {
    sendLobbyState(ws, username).catch(() => {});
    ws.on('close', () => removeUserConnection(usernameKey, ws));
    ws.on('error', () => {});
    return;
  }

  const roomCode = ws.roomCode;
  const room = getRoom(roomCode);
  const isDm = roomCode.startsWith('dm-');
  const isChannel = roomCode.startsWith('ch-');

  (async () => {
    if (isDm && ws.peer && dmRoomCode(username, ws.peer) === roomCode) {
      registerDmParticipants(roomCode, username, ws.peer);
    }
    if (isDm) clearUnread(roomCode, usernameKey);
    if (isChannel) { try { await joinChannel(roomCode, username); } catch (e) {} }

    // if this user already has a connection open in this room (e.g. reconnect), close the old one
    const existing = room.clients.get(username);
    if (existing && existing !== ws) { try { existing.close(); } catch (e) {} }
    room.clients.set(username, ws);

    // send initial state: current live (unburned) messages + settings + presence
    const liveMessages = Array.from(room.messages.entries()).map(([id, m]) => ({
      id, sender: m.sender, type: m.type, payload: m.payload, createdAt: m.createdAt,
      readBy: Object.fromEntries(m.readBy),
    }));

    const meta = { roomKind: isDm ? 'dm' : isChannel ? 'channel' : 'room' };
    if (isDm) {
      const entry = dmIndex.get(roomCode);
      const otherKey = entry && Object.keys(entry.participants).find(k => k !== usernameKey);
      meta.peer = otherKey ? entry.participants[otherKey] : ws.peer;
    } else if (isChannel) {
      const channel = await getChannel(roomCode).catch(() => null);
      if (channel) { meta.channelName = channel.name; meta.channelDescription = channel.description; meta.memberCount = channel.memberCount; }
    }

    send(ws, Object.assign({ type: 'joined', room: roomCode, timerSeconds: room.timerSeconds, presence: presenceList(room), messages: liveMessages }, meta));
    broadcastPresence(roomCode, room);
  })();

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

        // Deliver DMs to the recipient's account, not just this exact room:
        // if they're not currently sitting in this chat, bump their unread
        // count and push a live notification to wherever else they're
        // connected (lobby, another chat, etc). If they're offline entirely,
        // this still gets recorded so it's waiting for them on next login.
        if (isDm) {
          const entry = getDmEntry(roomCode);
          if (!Object.keys(entry.participants).length) {
            // DM room reached with no explicit peer registration (e.g. a
            // hand-typed room code) — fall back to whoever's connected so
            // the feature still degrades gracefully instead of breaking.
            for (const uname of room.clients.keys()) entry.participants[uname.toLowerCase()] = uname;
          }
          entry.lastMessage = { id, sender: username, preview: previewFor(record.type, record.payload), type: record.type, createdAt: record.createdAt };
          for (const [key, uname] of Object.entries(entry.participants)) {
            if (key === usernameKey) continue;
            if (!room.clients.has(uname)) {
              entry.unread[key] = (entry.unread[key] || 0) + 1;
              sendToUser(key, { type: 'dm-notify', room: roomCode, from: username, preview: entry.lastMessage.preview, msgType: record.type, createdAt: record.createdAt, unread: entry.unread[key] });
            }
          }
        }
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
        if (isDm) clearUnread(roomCode, usernameKey);
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
    removeUserConnection(usernameKey, ws);
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

Promise.all([initUserStore(), initChannelStore()])
  .then(() => {
    server.listen(PORT, () => {
      console.log(`Textme server listening on port ${PORT}`);
      if (!JWT_SECRET) console.warn('Reminder: set a real JWT_SECRET env var in production.');
    });
  })
  .catch((e) => {
    console.error('Failed to initialize user/channel store:', e);
    process.exit(1);
  });
