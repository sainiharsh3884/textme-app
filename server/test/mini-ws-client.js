// Minimal WebSocket client, test-only, for driving integration tests locally.
const net = require('net');
const crypto = require('crypto');
const { EventEmitter } = require('events');

function connect(host, port, path) {
  const emitter = new EventEmitter();
  const history = [];
  emitter.history = history;
  const socket = net.createConnection(port, host, () => {
    const key = crypto.randomBytes(16).toString('base64');
    socket.write(
      `GET ${path} HTTP/1.1\r\n` +
      `Host: ${host}:${port}\r\n` +
      'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
      `Sec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`
    );
  });
  let handshakeDone = false;
  let buf = Buffer.alloc(0);
  socket.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    if (!handshakeDone) {
      const idx = buf.indexOf('\r\n\r\n');
      if (idx === -1) return;
      const headerText = buf.slice(0, idx).toString();
      buf = buf.slice(idx + 4);
      handshakeDone = true;
      if (!/101/.test(headerText.split('\r\n')[0])) { emitter.emit('error', new Error('handshake failed: ' + headerText)); return; }
      emitter.emit('open');
    }
    parseFrames();
  });
  function parseFrames() {
    while (true) {
      if (buf.length < 2) return;
      const b1 = buf[1];
      let len = b1 & 0x7f, offset = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); offset = 4; }
      if (buf.length < offset + len) return;
      const payload = buf.slice(offset, offset + len);
      buf = buf.slice(offset + len);
      history.push(payload.toString());
      emitter.emit('message', payload.toString());
    }
  }
  function send(str) {
    const payload = Buffer.from(str);
    const maskKey = crypto.randomBytes(4);
    const masked = Buffer.alloc(payload.length);
    for (let i = 0; i < payload.length; i++) masked[i] = payload[i] ^ maskKey[i % 4];
    let header;
    if (payload.length < 126) header = Buffer.from([0x81, 0x80 | payload.length]);
    else { header = Buffer.alloc(4); header[0] = 0x81; header[1] = 0x80 | 126; header.writeUInt16BE(payload.length, 2); }
    socket.write(Buffer.concat([header, maskKey, masked]));
  }
  function close() { socket.end(); }
  return { on: (...a) => emitter.on(...a), send, close, history };
}
module.exports = { connect };
