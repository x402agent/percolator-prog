import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildRegisterArgv, MintRequestSchema, AgentMetadataSchema } from '../src/core/agents.js';
import { networkFor, decodeSecretKey, explorerUrl } from '../src/core/helius.js';

test('buildRegisterArgv: minimal name-only flags match the documented CLI', () => {
  assert.deepEqual(
    buildRegisterArgv({ name: 'My Agent' }),
    ['agents', 'register', '--name', 'My Agent'],
  );
});

test('buildRegisterArgv: full payload renders services + supported-trust as JSON', () => {
  const argv = buildRegisterArgv({
    name: 'My Agent',
    description: 'An autonomous trading agent',
    image: './avatar.png',
    services: [{ name: 'MCP', endpoint: 'https://myagent.com/mcp' }],
    supportedTrust: ['tee'],
    useIx: true,
  });
  assert.deepEqual(argv, [
    'agents', 'register',
    '--name', 'My Agent',
    '--description', 'An autonomous trading agent',
    '--image', './avatar.png',
    '--services', '[{"name":"MCP","endpoint":"https://myagent.com/mcp"}]',
    '--supported-trust', '["tee"]',
    '--use-ix',
  ]);
});

test('AgentMetadataSchema: type defaults to "agent" and arrays default to empty', () => {
  const md = AgentMetadataSchema.parse({ name: 'a', description: 'b' });
  assert.equal(md.type, 'agent');
  assert.deepEqual(md.services, []);
  assert.deepEqual(md.registrations, []);
  assert.deepEqual(md.supportedTrust, []);
});

test('MintRequestSchema: rejects non-URL uri', () => {
  const r = MintRequestSchema.safeParse({
    name: 'x',
    uri: 'not-a-url',
    metadata: { name: 'x', description: 'y' },
  });
  assert.equal(r.success, false);
});

test('MintRequestSchema: accepts a valid request', () => {
  const r = MintRequestSchema.parse({
    name: 'x',
    uri: 'https://example.com/agent.json',
    metadata: { name: 'x', description: 'y' },
  });
  assert.equal(r.name, 'x');
  assert.equal(r.metadata.type, 'agent');
});

test('networkFor: cluster names map to Metaplex network ids', () => {
  assert.equal(networkFor('mainnet-beta'), 'solana-mainnet');
  assert.equal(networkFor('devnet'), 'solana-devnet');
  assert.equal(networkFor('testnet'), 'solana-testnet');
});

test('decodeSecretKey: accepts JSON byte array (solana-keygen format)', () => {
  const bytes = Array.from({ length: 64 }, (_, i) => i % 256);
  const key = decodeSecretKey(JSON.stringify(bytes));
  assert.equal(key.length, 64);
  assert.equal(key[0], 0);
  assert.equal(key[63], 63);
});

test('decodeSecretKey: accepts base58 string', async () => {
  const bs58 = (await import('bs58')).default;
  const raw = new Uint8Array(64).fill(1);
  const encoded = bs58.encode(raw);
  const decoded = decodeSecretKey(encoded);
  assert.equal(decoded.length, 64);
  assert.equal(decoded[0], 1);
});

test('explorerUrl: omits cluster query for mainnet, includes it for devnet', () => {
  const addr = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  assert.equal(explorerUrl('mainnet-beta', addr), `https://explorer.solana.com/address/${addr}`);
  assert.equal(explorerUrl('devnet', addr), `https://explorer.solana.com/address/${addr}?cluster=devnet`);
});
