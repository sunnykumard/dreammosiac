const crypto = require('crypto');
const db = require('./db');

const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };
const KEY_LENGTH = 64;
const SESSION_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;
const rateLimitMap = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry) return { allowed: true, remaining: MAX_ATTEMPTS };
  if (entry.lockedUntil && entry.lockedUntil > now) {
    const waitSeconds = Math.ceil((entry.lockedUntil - now) / 1000);
    return { allowed: false, waitSeconds, error: `Too many failed attempts. Locked out for ${waitSeconds} seconds.` };
  }
  if (entry.lockedUntil && entry.lockedUntil <= now) {
    rateLimitMap.delete(ip);
    return { allowed: true, remaining: MAX_ATTEMPTS };
  }
  return { allowed: true, remaining: Math.max(0, MAX_ATTEMPTS - entry.count) };
}
function recordFailedAttempt(ip) {
  const now = Date.now();
  let entry = rateLimitMap.get(ip);
  if (!entry) entry = { count: 1, lastAttempt: now, lockedUntil: null };
  else {
    entry.count += 1;
    entry.lastAttempt = now;
    if (entry.count >= MAX_ATTEMPTS) entry.lockedUntil = now + LOCKOUT_MS;
  }
  rateLimitMap.set(ip, entry);
}
function clearRateLimit(ip) { rateLimitMap.delete(ip); }
function generateHighEntropyKey(prefix = 'dm_sec') {
  return `${prefix}_${crypto.randomBytes(32).toString('hex')}`;
}
function hashKey(plainKey, saltHex = null) {
  const salt = saltHex ? Buffer.from(saltHex, 'hex') : crypto.randomBytes(32);
  const hash = crypto.scryptSync(plainKey, salt, KEY_LENGTH, SCRYPT_PARAMS);
  return { salt: salt.toString('hex'), hash: hash.toString('hex') };
}
function verifyKey(plainKey, storedHashHex, storedSaltHex) {
  try {
    const salt = Buffer.from(storedSaltHex, 'hex');
    const storedHash = Buffer.from(storedHashHex, 'hex');
    const computedHash = crypto.scryptSync(plainKey, salt, KEY_LENGTH, SCRYPT_PARAMS);
    return crypto.timingSafeEqual(storedHash, computedHash);
  } catch { return false; }
}
async function isSystemConfigured() {
  const row = await db.queryOne("SELECT value FROM system_config WHERE key = 'is_configured'");
  return row ? row.value === 'true' : false;
}
async function performInitialSetup() {
  if (await isSystemConfigured()) throw new Error('System is already configured. Key generation is locked.');
  const ownerPlainKey = generateHighEntropyKey('dm_sec_owner');
  const partnerPlainKey = generateHighEntropyKey('dm_sec_partner');
  const ownerHash = hashKey(ownerPlainKey);
  const partnerHash = hashKey(partnerPlainKey);
  const ownerId = 'key_owner_' + crypto.randomBytes(8).toString('hex');
  const partnerId = 'key_partner_' + crypto.randomBytes(8).toString('hex');
  await db.exec("INSERT INTO security_keys (id, role, label, key_hash, salt, is_active) VALUES (?, 'owner', 'Owner Key (Admin)', ?, ?, 1)", [ownerId, ownerHash.hash, ownerHash.salt]);
  await db.exec("INSERT INTO security_keys (id, role, label, key_hash, salt, is_active) VALUES (?, 'partner', 'Partner Key (Member)', ?, ?, 1)", [partnerId, partnerHash.hash, partnerHash.salt]);
  await db.exec("INSERT OR REPLACE INTO system_config (key, value) VALUES ('is_configured', 'true')");
  return { ownerKey: ownerPlainKey, partnerKey: partnerPlainKey, createdAt: new Date().toISOString() };
}
async function authenticateWithKey(plainKey, ip = '', userAgent = '') {
  const rateLimit = checkRateLimit(ip);
  if (!rateLimit.allowed) {
    const err = new Error(rateLimit.error); err.status = 429; err.waitSeconds = rateLimit.waitSeconds; throw err;
  }
  if (!plainKey || typeof plainKey !== 'string') {
    recordFailedAttempt(ip); const err = new Error('Security key is required'); err.status = 400; throw err;
  }
  const activeKeys = await db.query('SELECT * FROM security_keys WHERE is_active = 1');
  let matchedKey = null;
  for (const k of activeKeys) if (verifyKey(plainKey.trim(), k.key_hash, k.salt)) { matchedKey = k; break; }
  if (!matchedKey) { recordFailedAttempt(ip); const err = new Error('Invalid security key'); err.status = 401; throw err; }
  clearRateLimit(ip);
  await db.exec('UPDATE security_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?', [matchedKey.id]);
  const sessionToken = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + SESSION_EXPIRY_MS;
  await db.exec('INSERT INTO sessions (token, role, key_id, ip, user_agent, expires_at) VALUES (?, ?, ?, ?, ?, ?)', [sessionToken, matchedKey.role, matchedKey.id, ip, userAgent, expiresAt]);
  return { token: sessionToken, user: { role: matchedKey.role, label: matchedKey.label, keyId: matchedKey.id }, expiresAt };
}
async function validateSession(token) {
  if (!token || typeof token !== 'string') return null;
  const session = await db.queryOne(`SELECT s.*, k.label, k.is_active FROM sessions s JOIN security_keys k ON s.key_id = k.id WHERE s.token = ?`, [token]);
  if (!session) return null;
  if (session.is_active !== 1 || session.expires_at < Date.now()) {
    await db.exec('DELETE FROM sessions WHERE token = ?', [token]); return null;
  }
  return { token: session.token, role: session.role, label: session.label, keyId: session.key_id, expiresAt: session.expires_at };
}
async function revokeSession(token) { if (token) await db.exec('DELETE FROM sessions WHERE token = ?', [token]); }
async function rotateKey(role, ownerRole) {
  if (ownerRole !== 'owner') { const err = new Error('Only the owner can rotate security keys'); err.status = 403; throw err; }
  if (!['partner', 'owner'].includes(role)) { const err = new Error("Invalid role to rotate. Must be 'partner' or 'owner'"); err.status = 400; throw err; }
  await db.exec('UPDATE security_keys SET is_active = 0 WHERE role = ?', [role]);
  await db.exec('DELETE FROM sessions WHERE role = ?', [role]);
  const newPlainKey = generateHighEntropyKey(`dm_sec_${role}`);
  const newHash = hashKey(newPlainKey);
  const newId = `key_${role}_` + crypto.randomBytes(8).toString('hex');
  const label = role === 'owner' ? 'Owner Key (Admin)' : 'Partner Key (Member)';
  await db.exec('INSERT INTO security_keys (id, role, label, key_hash, salt, is_active) VALUES (?, ?, ?, ?, ?, 1)', [newId, role, label, newHash.hash, newHash.salt]);
  return { role, newKey: newPlainKey, createdAt: new Date().toISOString() };
}
async function revokePartnerKey(ownerRole) {
  if (ownerRole !== 'owner') { const err = new Error('Only the owner can revoke security keys'); err.status = 403; throw err; }
  await db.exec("UPDATE security_keys SET is_active = 0 WHERE role = 'partner'");
  await db.exec("DELETE FROM sessions WHERE role = 'partner'");
  return { revoked: true, role: 'partner' };
}
async function listKeys(ownerRole) {
  if (ownerRole !== 'owner') { const err = new Error('Only the owner can list security keys'); err.status = 403; throw err; }
  return db.query('SELECT id, role, label, is_active, created_at, last_used_at FROM security_keys ORDER BY created_at DESC');
}
module.exports = { isSystemConfigured, performInitialSetup, authenticateWithKey, validateSession, revokeSession, rotateKey, revokePartnerKey, listKeys, checkRateLimit };
