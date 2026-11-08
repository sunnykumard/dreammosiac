const http = require('http');
const assert = require('assert');

const BASE_URL = 'http://127.0.0.1:3001';

function request(method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: { 'Content-Type': 'application/json', ...headers }
    };
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (e) { json = data; }
        resolve({ statusCode: res.statusCode, headers: res.headers, body: json });
      });
    });
    req.on('error', reject);
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

async function runTests() {
  console.log('=== Starting DreamMosaic Backend Automated Tests ===\\n');
  let ownerKey = '', partnerKey = '', ownerToken = '', partnerToken = '';

  console.log('Test 1: Status endpoint');
  const resStatus = await request('GET', '/api/status');
  assert.strictEqual(resStatus.statusCode, 200);
  console.log('✔ Status is online. Requires setup:', resStatus.body.requiresSetup);

  console.log('\\nTest 2: First-time Owner Setup & Key Generation');
  const resSetup = await request('POST', '/api/auth/setup');
  assert.strictEqual(resSetup.statusCode, 200);
  assert(resSetup.body.ownerKey.startsWith('dm_sec_owner_'));
  assert(resSetup.body.partnerKey.startsWith('dm_sec_partner_'));
  ownerKey = resSetup.body.ownerKey; partnerKey = resSetup.body.partnerKey;

  console.log('\\nTest 3: Prevent duplicate setup attempts');
  assert.strictEqual((await request('POST', '/api/auth/setup')).statusCode, 400);

  console.log('\\nTest 4: Unauthorized access blocked without token');
  assert.strictEqual((await request('GET', '/api/photos')).statusCode, 401);
  assert.strictEqual((await request('GET', '/api/auth/keys')).statusCode, 401);

  console.log('\\nTest 5: Invalid key login attempt');
  assert.strictEqual((await request('POST', '/api/auth/login', { key: 'invalid_fake_key_123' })).statusCode, 401);

  console.log('\\nTest 6: Valid Owner Key login');
  const resOwnerLogin = await request('POST', '/api/auth/login', { key: ownerKey });
  assert.strictEqual(resOwnerLogin.statusCode, 200);
  assert.strictEqual(resOwnerLogin.body.user.role, 'owner');
  assert(resOwnerLogin.body.token);
  assert(resOwnerLogin.headers['set-cookie']);
  ownerToken = resOwnerLogin.body.token;

  console.log('\\nTest 7: Valid Partner Key login');
  const resPartnerLogin = await request('POST', '/api/auth/login', { key: partnerKey });
  assert.strictEqual(resPartnerLogin.statusCode, 200);
  assert.strictEqual(resPartnerLogin.body.user.role, 'partner');
  partnerToken = resPartnerLogin.body.token;

  console.log('\\nTest 8: Session verification endpoint');
  const resSession = await request('GET', '/api/auth/session', null, { Authorization: `Bearer ${ownerToken}` });
  assert.strictEqual(resSession.statusCode, 200);
  assert.strictEqual(resSession.body.user.role, 'owner');

  console.log('\\nTest 9: Role-based access control (RBAC)');
  assert.strictEqual((await request('GET', '/api/auth/keys', null, { Authorization: `Bearer ${partnerToken}` })).statusCode, 403);
  const resOwnerKeys = await request('GET', '/api/auth/keys', null, { Authorization: `Bearer ${ownerToken}` });
  assert.strictEqual(resOwnerKeys.statusCode, 200);
  assert(Array.isArray(resOwnerKeys.body.keys));

  console.log('\\nTest 10: Authenticated photo upload & deduplication');
  const testPng = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';
  const resUpload1 = await request('POST', '/api/photos/upload', { filename: 'red_dot.png', dataUrl: testPng }, { Authorization: `Bearer ${ownerToken}` });
  assert.strictEqual(resUpload1.statusCode, 201);
  const photoId = resUpload1.body.photo.id;
  assert(photoId);
  const resUploadDup = await request('POST', '/api/photos/upload', { filename: 'red_dot_copy.png', dataUrl: testPng }, { Authorization: `Bearer ${ownerToken}` });
  assert.strictEqual(resUploadDup.statusCode, 200);
  assert.strictEqual(resUploadDup.body.duplicate, true);

  console.log('\\nTest 11: Private image protection');
  assert.strictEqual((await request('GET', `/api/photos/${photoId}`)).statusCode, 401);
  assert.strictEqual((await request('GET', `/api/photos/${photoId}`, null, { Authorization: `Bearer ${partnerToken}` })).statusCode, 200);

  console.log('\\nTest 12: Key Rotation by Owner');
  const resRotate = await request('POST', '/api/auth/keys/rotate', { role: 'partner' }, { Authorization: `Bearer ${ownerToken}` });
  assert.strictEqual(resRotate.statusCode, 200);
  assert(resRotate.body.newKey.startsWith('dm_sec_partner_'));
  const newPartnerKey = resRotate.body.newKey;
  assert.strictEqual((await request('GET', '/api/auth/session', null, { Authorization: `Bearer ${partnerToken}` })).statusCode, 401);
  assert.strictEqual((await request('POST', '/api/auth/login', { key: partnerKey })).statusCode, 401);
  assert.strictEqual((await request('POST', '/api/auth/login', { key: newPartnerKey })).statusCode, 200);

  console.log('\\nTest 13: Rate limiting on failed login attempts');
  let rateLimitHit = false;
  for (let i = 0; i < 6; i++) {
    const res = await request('POST', '/api/auth/login', { key: 'wrong_key_' + i });
    if (res.statusCode === 429) { rateLimitHit = true; break; }
  }
  assert(rateLimitHit, 'Rate limit was triggered');

  console.log('\\nALL 13 BACKEND SECURITY & FUNCTIONAL TESTS PASSED!');
}

runTests().catch((err) => {
  console.error('Test failed with error:', err);
  process.exit(1);
});
