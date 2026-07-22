const http = require('http');
const { connect } = require('./mini-ws-client');

const HOST = 'localhost', PORT = 8080;
let failures = 0;
function ok(cond, label) { if (cond) console.log('PASS', label); else { console.log('FAIL', label); failures++; } }

function apiPost(path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({ host: HOST, port: PORT, path, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } }, (res) => {
      let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(d) }));
    });
    req.on('error', reject); req.write(data); req.end();
  });
}

const consumedIdx = new WeakMap();
function wsOnce(ws, matchFn, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    let idx = consumedIdx.get(ws) || 0;
    for (; idx < ws.history.length; idx++) {
      const msg = JSON.parse(ws.history[idx]);
      if (matchFn(msg)) { consumedIdx.set(ws, idx + 1); resolve(msg); return; }
    }
    consumedIdx.set(ws, idx);
    const t = setTimeout(() => reject(new Error('timeout waiting for ' + matchFn)), timeoutMs);
    function handler(raw) {
      const msg = JSON.parse(raw);
      const cur = consumedIdx.get(ws) || 0;
      consumedIdx.set(ws, cur + 1);
      if (matchFn(msg)) { clearTimeout(t); resolve(msg); }
    }
    ws.on('message', handler);
  });
}

async function main() {
  // --- signup two users ---
  const a = await apiPost('/api/signup', { username: 'alice_' + Date.now(), password: 'password1' });
  const b = await apiPost('/api/signup', { username: 'bob_' + Date.now(), password: 'password2' });
  ok(a.status === 200 && a.body.token, 'signup alice');
  ok(b.status === 200 && b.body.token, 'signup bob');

  const room = 'testroom' + Date.now();
  const wsA = connect(HOST, PORT, `/ws?token=${a.body.token}&room=${room}`);
  const wsB = connect(HOST, PORT, `/ws?token=${b.body.token}&room=${room}`);

  await new Promise((res) => wsA.on('open', res));
  const joinedA = await wsOnce(wsA, m => m.type === 'joined');
  ok(joinedA.timerSeconds === 300, 'default timer is 300s');

  await new Promise((res) => wsB.on('open', res));
  await wsOnce(wsB, m => m.type === 'joined');

  // alice should see presence update when bob joins
  const presenceA = await wsOnce(wsA, m => m.type === 'presence' && m.users.length === 2);
  ok(presenceA.users.length === 2, 'presence shows both users');

  // set a short timer for the test
  wsA.send(JSON.stringify({ type: 'settings', timerSeconds: 2 }));
  await wsOnce(wsB, m => m.type === 'settings' && m.timerSeconds === 2);
  ok(true, 'settings change propagated to bob');

  // alice sends a text message
  wsA.send(JSON.stringify({ type: 'message', msgType: 'text', payload: { text: 'hello bob' } }));
  const msgOnB = await wsOnce(wsB, m => m.type === 'message');
  ok(msgOnB.payload.text === 'hello bob', 'bob received the message');
  const msgId = msgOnB.id;

  // bob "reads" it (client would auto-send this)
  wsB.send(JSON.stringify({ type: 'read', id: msgId }));
  const receipt = await wsOnce(wsA, m => m.type === 'read-receipt' && m.id === msgId);
  ok(receipt.reader === 'bob_'.slice(0,4) || receipt.reader.startsWith('bob_'), 'alice got read receipt from bob');

  // wait for the 2s timer to fire the delete
  const deleted = await wsOnce(wsA, m => m.type === 'message-deleted' && m.id === msgId, 5000);
  ok(!!deleted, 'message auto-deleted after read timer elapsed');
  const deletedOnB = await wsOnce(wsB, m => m.type === 'message-deleted' && m.id === msgId, 5000);
  ok(!!deletedOnB, 'delete propagated to bob too');

  // --- call signaling relay ---
  wsA.send(JSON.stringify({ type: 'call-offer', callId: 'call1', callType: 'audio', sdp: { fake: 'offer-sdp' } }));
  const incoming = await wsOnce(wsB, m => m.type === 'incoming-call');
  ok(incoming.from && incoming.callId === 'call1' && incoming.sdp.fake === 'offer-sdp', 'bob received the call offer');

  wsB.send(JSON.stringify({ type: 'call-answer', callId: 'call1', to: incoming.from, sdp: { fake: 'answer-sdp' } }));
  const answerOnA = await wsOnce(wsA, m => m.type === 'call-answer');
  ok(answerOnA.sdp.fake === 'answer-sdp', 'alice received the call answer, relayed correctly');

  wsA.send(JSON.stringify({ type: 'call-ice', callId: 'call1', to: answerOnA.from, candidate: { fake: 'ice-a' } }));
  const iceOnB = await wsOnce(wsB, m => m.type === 'call-ice');
  ok(iceOnB.candidate.fake === 'ice-a', 'ICE candidate relayed from alice to bob');

  wsA.send(JSON.stringify({ type: 'call-end', callId: 'call1', to: answerOnA.from }));
  const endedOnB = await wsOnce(wsB, m => m.type === 'call-ended');
  ok(endedOnB.callId === 'call1', 'call-end relayed to bob');

  wsA.close(); wsB.close();

  console.log(failures === 0 ? '\nALL TESTS PASSED' : `\n${failures} TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch(e => { console.error('Test crashed:', e); process.exit(1); });
