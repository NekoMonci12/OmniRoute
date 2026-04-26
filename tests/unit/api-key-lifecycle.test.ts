import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const TEST_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "omr-apikey-lifecycle-"));
process.env.DATA_DIR = TEST_DATA_DIR;
process.env.API_KEY_SECRET = "test-secret";

const core = await import("../../src/lib/db/core.ts");
const apiKeysDb = await import("../../src/lib/db/apiKeys.ts");

function reset() {
  core.resetDbInstance();
  apiKeysDb.resetApiKeyState();
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
  fs.mkdirSync(TEST_DATA_DIR, { recursive: true });
}

test.beforeEach(() => {
  reset();
});

test.after(() => {
  fs.rmSync(TEST_DATA_DIR, { recursive: true, force: true });
});

async function makeKey(name = "lifecycle-test", machineId = "machine-lifecycle") {
  const created = await apiKeysDb.createApiKey(name, machineId);
  assert.ok(created?.key, "createApiKey returned a key");
  return created;
}

test("validateApiKey returns true for a fresh active key", async () => {
  const created = await makeKey();
  assert.equal(await apiKeysDb.validateApiKey(created.key), true);
});

test("validateApiKey rejects revoked keys after revokeApiKey", async () => {
  const created = await makeKey();
  assert.equal(await apiKeysDb.validateApiKey(created.key), true);

  const ok = await apiKeysDb.revokeApiKey(created.id);
  assert.equal(ok, true);

  assert.equal(await apiKeysDb.validateApiKey(created.key), false);
});

test("validateApiKey rejects keys whose expires_at has passed", async () => {
  const created = await makeKey();
  const past = new Date(Date.now() - 60_000).toISOString();
  const ok = await apiKeysDb.setApiKeyExpiry(created.id, past);
  assert.equal(ok, true);
  assert.equal(await apiKeysDb.validateApiKey(created.key), false);
});

test("validateApiKey accepts keys with future expires_at", async () => {
  const created = await makeKey();
  const future = new Date(Date.now() + 60 * 60_000).toISOString();
  const ok = await apiKeysDb.setApiKeyExpiry(created.id, future);
  assert.equal(ok, true);
  assert.equal(await apiKeysDb.validateApiKey(created.key), true);
});

test("validateApiKey rejects deactivated keys (is_active=false)", async () => {
  const created = await makeKey();
  const ok = await apiKeysDb.updateApiKeyPermissions(created.id, { isActive: false });
  assert.equal(ok, true);
  assert.equal(await apiKeysDb.validateApiKey(created.key), false);
});

test("revokeApiKey is idempotent and returns false for missing id", async () => {
  const created = await makeKey();
  assert.equal(await apiKeysDb.revokeApiKey(created.id), true);
  assert.equal(await apiKeysDb.revokeApiKey(created.id), true);
  assert.equal(await apiKeysDb.revokeApiKey("00000000-0000-0000-0000-000000000000"), false);
});

test("getApiKeyMetadata exposes lifecycle and policy fields", async () => {
  const created = await makeKey();
  await apiKeysDb.setApiKeyExpiry(created.id, new Date(Date.now() + 86_400_000).toISOString());

  const md = await apiKeysDb.getApiKeyMetadata(created.key);
  assert.ok(md);
  assert.equal(md!.isActive, true);
  assert.equal(md!.revokedAt, null);
  assert.ok(md!.expiresAt && Date.parse(md!.expiresAt) > Date.now());
  assert.deepEqual(md!.ipAllowlist, []);
  assert.deepEqual(md!.scopes, []);
});
