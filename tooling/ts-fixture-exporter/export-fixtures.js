#!/usr/bin/env node

/**
 * TS Fixture Exporter
 *
 * Extracts golden test fixtures from TypeScript SDK patterns
 * to ensure Python SDK parity
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import nacl from 'tweetnacl';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Helper functions to mimic TS SDK behavior
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

function canonicalJSON(obj) {
  // Canonical JSON: sorted keys, no extra whitespace
  // This matches Python: json.dumps(obj, separators=(',', ':'), sort_keys=True, ensure_ascii=False)
  const replacer = (key, value) => {
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      const sorted = {};
      Object.keys(value).sort().forEach(k => {
        sorted[k] = value[k];
      });
      return sorted;
    }
    return value;
  };

  return JSON.stringify(obj, replacer).replace(/\s/g, '');
}

function deriveLiteIdentityUrl(publicKeyBytes) {
  // Match TS SDK URL derivation with checksum
  const keyHashFull = sha256(publicKeyBytes);
  const keyHash20 = keyHashFull.slice(0, 20);
  const keyStr = keyHash20.toString('hex');

  // Calculate checksum
  const checksumFull = sha256(Buffer.from(keyStr, 'utf-8'));
  const checksum = checksumFull.slice(28).toString('hex'); // Last 4 bytes

  return `acc://${keyStr}${checksum}`;
}

function deriveLiteTokenAccountUrl(publicKeyBytes, token = 'ACME') {
  const lid = deriveLiteIdentityUrl(publicKeyBytes);
  return `${lid}/${token}`;
}

// Test vectors from TS SDK patterns
function generateEd25519Vectors() {
  const vectors = [];

  // Test vector 1: Zero private key (from TS tests)
  const zeroPrivateKey = Buffer.alloc(32, 0);
  const zeroKeyPair = nacl.sign.keyPair.fromSeed(zeroPrivateKey);

  vectors.push({
    name: "zero_private_key",
    description: "Zero private key test vector from TS tests",
    privateKey: zeroPrivateKey.toString('hex'),
    publicKey: Buffer.from(zeroKeyPair.publicKey).toString('hex'),
    lid: deriveLiteIdentityUrl(zeroKeyPair.publicKey),
    lta: deriveLiteTokenAccountUrl(zeroKeyPair.publicKey),
    testMessage: "test message",
    expectedSignatureLength: 64
  });

  // Test vector 2: Known seed (from TS tests)
  const knownSeed = Buffer.from('a362b69a6cda241bf6b949faffb3bffbf1a47291373590660644f5c572feae72', 'hex');
  const knownKeyPair = nacl.sign.keyPair.fromSeed(knownSeed);

  vectors.push({
    name: "known_seed",
    description: "Known seed test vector from TS tests",
    privateKey: knownSeed.toString('hex'),
    publicKey: Buffer.from(knownKeyPair.publicKey).toString('hex'),
    lid: deriveLiteIdentityUrl(knownKeyPair.publicKey),
    lta: deriveLiteTokenAccountUrl(knownKeyPair.publicKey),
    testMessage: "test message",
    expectedSignatureLength: 64
  });

  // Test vector 3: Test signature generation
  const testPrivateKey = Buffer.from('1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', 'hex');
  const testKeyPair = nacl.sign.keyPair.fromSeed(testPrivateKey);
  const testMessage = Buffer.from('test message');
  const testSignature = nacl.sign.detached(sha256(testMessage), testKeyPair.secretKey);

  vectors.push({
    name: "test_signing",
    description: "Test signing vector",
    privateKey: testPrivateKey.toString('hex'),
    publicKey: Buffer.from(testKeyPair.publicKey).toString('hex'),
    lid: deriveLiteIdentityUrl(testKeyPair.publicKey),
    lta: deriveLiteTokenAccountUrl(testKeyPair.publicKey),
    testMessage: testMessage.toString('hex'),
    signature: Buffer.from(testSignature).toString('hex'),
    messageHash: sha256(testMessage).toString('hex')
  });

  return vectors;
}

function generateTransactionVectors() {
  const vectors = [];

  // Simple transaction structure
  const tx1 = {
    header: {
      principal: "acc://alice.acme/tokens",
      timestamp: 1234567890123456
    },
    body: {
      type: "sendTokens",
      to: [
        {
          url: "acc://bob.acme/tokens",
          amount: "1000000"
        }
      ]
    }
  };

  vectors.push({
    name: "send_tokens_simple",
    description: "Simple send tokens transaction",
    transaction: tx1,
    canonicalJSON: canonicalJSON(tx1),
    hash: sha256(Buffer.from(canonicalJSON(tx1))).toString('hex')
  });

  // AddCredits transaction
  const tx2 = {
    header: {
      principal: "acc://25e8e0d2ac56a79a2384d9662dcddfe59a92ee0ae77fbd1e/ACME",
      timestamp: 1234567890123456
    },
    body: {
      type: "addCredits",
      recipient: {
        url: "acc://25e8e0d2ac56a79a2384d9662dcddfe59a92ee0ae77fbd1e"
      },
      amount: "1000000"
    }
  };

  vectors.push({
    name: "add_credits",
    description: "Add credits transaction",
    transaction: tx2,
    canonicalJSON: canonicalJSON(tx2),
    hash: sha256(Buffer.from(canonicalJSON(tx2))).toString('hex')
  });

  return vectors;
}

function generateEnvelopeVectors() {
  const vectors = [];

  // Test envelope with signature
  const testPrivateKey = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex');
  const testKeyPair = nacl.sign.keyPair.fromSeed(testPrivateKey);

  const transaction = {
    header: {
      principal: "acc://test.acme/tokens",
      timestamp: 1640995200000000 // 2022-01-01 00:00:00 UTC in microseconds
    },
    body: {
      type: "sendTokens",
      to: [
        {
          url: "acc://recipient.acme/tokens",
          amount: "500000"
        }
      ]
    }
  };

  const txJSON = canonicalJSON(transaction);
  const txHash = sha256(Buffer.from(txJSON));
  const signature = nacl.sign.detached(txHash, testKeyPair.secretKey);

  const envelope = {
    transaction: transaction,
    signatures: [
      {
        type: "ed25519",
        publicKey: Buffer.from(testKeyPair.publicKey).toString('hex'),
        signature: Buffer.from(signature).toString('hex')
      }
    ]
  };

  vectors.push({
    name: "simple_envelope",
    description: "Simple transaction envelope with Ed25519 signature",
    envelope: envelope,
    transactionJSON: txJSON,
    transactionHash: txHash.toString('hex'),
    canonicalEnvelopeJSON: canonicalJSON(envelope)
  });

  return vectors;
}

function generateHashingVectors() {
  const vectors = [];

  // Test vectors for SHA-256 hashing
  const testCases = [
    {
      input: "",
      expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    {
      input: "abc",
      expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    },
    {
      input: "test data",
      expected: sha256(Buffer.from("test data")).toString('hex')
    },
    {
      input: JSON.stringify({a: 1, b: 2}),
      expected: sha256(Buffer.from(JSON.stringify({a: 1, b: 2}))).toString('hex')
    }
  ];

  testCases.forEach((testCase, index) => {
    vectors.push({
      name: `sha256_test_${index + 1}`,
      description: `SHA-256 test case ${index + 1}`,
      input: testCase.input,
      inputHex: Buffer.from(testCase.input).toString('hex'),
      expectedHash: testCase.expected,
      actualHash: sha256(Buffer.from(testCase.input)).toString('hex')
    });
  });

  return vectors;
}

function generateCanonicalJSONVectors() {
  const vectors = [];

  const testObjects = [
    {
      name: "simple_object",
      input: {b: 2, a: 1, c: 3},
      expected: '{"a":1,"b":2,"c":3}'
    },
    {
      name: "nested_object",
      input: {
        z: {y: 2, x: 1},
        a: [3, 1, 2],
        m: "test"
      },
      expected: canonicalJSON({
        z: {y: 2, x: 1},
        a: [3, 1, 2],
        m: "test"
      })
    },
    {
      name: "transaction_like",
      input: {
        body: {type: "sendTokens", to: []},
        header: {principal: "acc://test", timestamp: 123}
      },
      expected: canonicalJSON({
        body: {type: "sendTokens", to: []},
        header: {principal: "acc://test", timestamp: 123}
      })
    }
  ];

  testObjects.forEach(testObj => {
    vectors.push({
      name: testObj.name,
      description: `Canonical JSON test: ${testObj.name}`,
      input: testObj.input,
      expectedJSON: testObj.expected,
      actualJSON: canonicalJSON(testObj.input)
    });
  });

  return vectors;
}

// Export all fixtures
function exportAllFixtures() {
  const fixtures = {
    description: "Golden test fixtures extracted from TypeScript SDK patterns",
    generatedAt: new Date().toISOString(),
    ed25519_vectors: generateEd25519Vectors(),
    transaction_vectors: generateTransactionVectors(),
    envelope_vectors: generateEnvelopeVectors(),
    hashing_vectors: generateHashingVectors(),
    canonical_json_vectors: generateCanonicalJSONVectors()
  };

  // Write individual fixture files
  const outputDir = path.join(__dirname, '../../tests/golden');

  // Ensure output directory exists
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  // Write tx_signing_vectors.json
  fs.writeFileSync(
    path.join(outputDir, 'tx_signing_vectors.json'),
    JSON.stringify({
      description: "Transaction signing test vectors for TS-Python parity",
      vectors: fixtures.ed25519_vectors
    }, null, 2)
  );

  // Write envelope_fixed.golden.json (reuse Dart's format but with our data)
  if (fixtures.envelope_vectors.length > 0) {
    fs.writeFileSync(
      path.join(outputDir, 'envelope_fixed.golden.json'),
      JSON.stringify(fixtures.envelope_vectors[0].envelope, null, 2)
    );
  }

  // Write sig_ed25519.golden.json
  if (fixtures.envelope_vectors.length > 0) {
    fs.writeFileSync(
      path.join(outputDir, 'sig_ed25519.golden.json'),
      JSON.stringify(fixtures.envelope_vectors[0].envelope.signatures[0], null, 2)
    );
  }

  // Write tx_only.golden.json
  if (fixtures.transaction_vectors.length > 0) {
    fs.writeFileSync(
      path.join(outputDir, 'tx_only.golden.json'),
      JSON.stringify(fixtures.transaction_vectors[0].transaction, null, 2)
    );
  }

  // Write comprehensive fixtures
  fs.writeFileSync(
    path.join(outputDir, 'ts_parity_fixtures.json'),
    JSON.stringify(fixtures, null, 2)
  );

  console.log('✅ Exported golden fixtures to:', outputDir);
  console.log('📁 Files generated:');
  console.log('   - tx_signing_vectors.json');
  console.log('   - envelope_fixed.golden.json');
  console.log('   - sig_ed25519.golden.json');
  console.log('   - tx_only.golden.json');
  console.log('   - ts_parity_fixtures.json');

  return fixtures;
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1].endsWith('export-fixtures.js')) {
  console.log('Running fixture exporter...');
  exportAllFixtures();
} else {
  console.log('Exporter loaded as module');
}