'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const { runCrypto } = require('../src/crypto.cjs');

const aesKey = '000102030405060708090a0b0c0d0e0f';
const sm3Abc = '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0';

test('SM3 计算已知摘要，并核对 Hex 和 Base64 摘要', async () => {
  assert.deepEqual(await runCrypto({ algorithm: 'sm3', operation: 'hash', input: 'abc' }), {
    output: sm3Abc,
  });

  const base64 = Buffer.from(sm3Abc, 'hex').toString('base64');
  assert.deepEqual(await runCrypto({
    algorithm: 'sm3', operation: 'verify', input: 'abc', encoding: 'base64', expected: base64,
  }), { output: base64, verified: true });
  assert.deepEqual(await runCrypto({
    algorithm: 'sm3', operation: 'verify', input: 'abc', expected: '00'.repeat(32),
  }), { output: sm3Abc, verified: false });
});

test('AES-GCM 原始模式符合已知向量并拒绝被修改的认证标签', async () => {
  const parameters = {
    algorithm: 'aes-gcm', format: 'raw', keyFormat: 'hex', encoding: 'hex',
    key: '00'.repeat(16), iv: '00'.repeat(12),
  };
  const plaintext = '\0'.repeat(16);
  const encrypted = await runCrypto({ ...parameters, operation: 'encrypt', input: plaintext });
  assert.deepEqual(encrypted, {
    output: '0388dace60b6a392f328c2b971b2fe78',
    iv: parameters.iv,
    tag: 'ab6e47d42cec13bdf53a67b21257bddf',
  });

  const decrypt = { ...parameters, operation: 'decrypt', input: encrypted.output };
  assert.deepEqual(await runCrypto({ ...decrypt, tag: encrypted.tag }), { output: plaintext });
  await assert.rejects(runCrypto({ ...decrypt, tag: '00'.repeat(16) }), /解密失败/);
});

test('AES-CBC 和 SM4-CBC 原始模式保留标准分组结果并使用 PKCS#7 填充', async () => {
  const cases = [
    {
      algorithm: 'aes-cbc', key: '2b7e151628aed2a6abf7158809cf4f3c',
      iv: '6bc0bce12a459991e134741a7f9e1925', initialBlock: '7649abac8119b246cee98e9b12e9197d',
    },
    {
      algorithm: 'sm4-cbc', key: '0123456789abcdeffedcba9876543210',
      iv: '0123456789abcdeffedcba9876543210', initialBlock: '681edf34d206965e86b3e94f536e4246',
    },
  ];

  // CBC 将第一块明文与 IV 异或。此处用 NUL 文本和相应 IV 重现标准分组输入。
  const plaintext = '\0'.repeat(16);
  for (const { initialBlock, ...vector } of cases) {
    const parameters = { ...vector, format: 'raw', keyFormat: 'hex', encoding: 'hex' };
    const encrypted = await runCrypto({ ...parameters, operation: 'encrypt', input: plaintext });
    assert.equal(encrypted.output.slice(0, 32), initialBlock);
    assert.equal(encrypted.output.length, 64);
    assert.deepEqual(await runCrypto({ ...parameters, operation: 'decrypt', input: encrypted.output }), {
      output: plaintext,
    });
    await assert.rejects(runCrypto({ ...parameters, operation: 'decrypt', input: initialBlock }), /解密失败/);
    await assert.rejects(runCrypto({ ...parameters, operation: 'decrypt', input: `${encrypted.output}00` }), /解密失败/);
  }
});

test('AES-GCM 密码密文包支持 Unicode、随机盐和 IV，并拒绝错误密码', async () => {
  const input = '\uFEFF中文 🔐\n末尾空格  ';
  const parameters = { algorithm: 'aes-gcm', key: ' 测试密码 🔑 ' };
  const first = await runCrypto({ ...parameters, operation: 'encrypt', input });
  const second = await runCrypto({ ...parameters, operation: 'encrypt', input });
  assert.notEqual(first.output, second.output);
  assert.deepEqual(await runCrypto({ ...parameters, operation: 'decrypt', input: first.output }), {
    output: input,
  });
  await assert.rejects(runCrypto({
    ...parameters, operation: 'decrypt', input: first.output, key: '错误的密码',
  }), /解密失败/);
});

test('CBC 密文包验证密文和 IV 的完整性', async () => {
  for (const algorithm of ['aes-cbc', 'sm4-cbc']) {
    const parameters = { algorithm, key: aesKey, keyFormat: 'hex', encoding: 'hex' };
    const plaintext = '中文加解密';
    const { output } = await runCrypto({ ...parameters, operation: 'encrypt', input: plaintext });
    assert.deepEqual(await runCrypto({ ...parameters, operation: 'decrypt', input: output }), {
      output: plaintext,
    });

    for (const position of [8, 24]) {
      const modified = Buffer.from(output, 'hex');
      modified[position] ^= 1;
      await assert.rejects(runCrypto({
        ...parameters, operation: 'decrypt', input: modified.toString('hex'),
      }), /解密失败/);
    }
  }
});

test('原始模式支持自动生成 IV，允许 AES-GCM 加解密空文本', async () => {
  const parameters = {
    algorithm: 'aes-gcm', format: 'raw', keyFormat: 'base64',
    key: Buffer.alloc(24, 12).toString('base64'),
  };
  const encrypted = await runCrypto({ ...parameters, operation: 'encrypt', input: '' });
  assert.equal(encrypted.output, '');
  assert.match(encrypted.iv, /^[\da-f]{24}$/);
  assert.match(encrypted.tag, /^[\da-f]{32}$/);
  assert.deepEqual(await runCrypto({
    ...parameters, operation: 'decrypt', input: encrypted.output, iv: encrypted.iv, tag: encrypted.tag,
  }), { output: '' });
});

test('错误的模式、编码、长度和算法选择得到明确反馈', async () => {
  const parameters = { algorithm: 'aes-cbc', key: aesKey, keyFormat: 'hex' };
  await assert.rejects(runCrypto({ ...parameters, operation: 'encrypt', input: '', key: 'zz' }), /有效的 Hex/);
  await assert.rejects(runCrypto({ ...parameters, operation: 'encrypt', input: '', key: '12' }), /密钥长度/);
  await assert.rejects(runCrypto({
    ...parameters, operation: 'encrypt', input: '', format: 'raw', keyFormat: 'password',
  }), /原始密文模式需要/);
  await assert.rejects(runCrypto({ ...parameters, operation: 'decrypt', input: 'AB' }), /有效的 Base64/);
  await assert.rejects(runCrypto({ ...parameters, operation: 'encrypt', input: '汉'.repeat(1024 * 1024) }), /1 MiB/);

  const { output } = await runCrypto({ ...parameters, operation: 'encrypt', input: 'hello' });
  await assert.rejects(runCrypto({
    ...parameters, algorithm: 'aes-gcm', operation: 'decrypt', input: output,
  }), /所选算法/);
});
