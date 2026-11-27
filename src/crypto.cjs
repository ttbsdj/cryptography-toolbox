'use strict';

const {
  createCipheriv,
  createDecipheriv,
  createHmac,
  getCiphers,
  hkdfSync,
  randomBytes,
  scrypt,
  timingSafeEqual,
} = require('node:crypto');
const { promisify, TextDecoder } = require('node:util');
const { sm3, sm4 } = require('sm-crypto');

const derivePasswordKey = promisify(scrypt);
const passwordParameters = { N: 2 ** 16, r: 8, p: 2, maxmem: 96 * 1024 * 1024 };
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const supportedCiphers = new Set(getCiphers());
const blockSize = 16;

const aesKeyLengths = [16, 24, 32];
const ciphers = {
  'aes-gcm': { id: 1, keyLengths: aesKeyLengths, passwordKeyLength: 32, ivLength: 12, tagLength: 16, gcm: true },
  'aes-cbc': { id: 2, keyLengths: aesKeyLengths, passwordKeyLength: 32, ivLength: 16, tagLength: 32, gcm: false },
  'sm4-cbc': { id: 3, keyLengths: [16], passwordKeyLength: 16, ivLength: 16, tagLength: 32, gcm: false },
};

const envelopeMagic = Buffer.from('CMST', 'ascii');
const envelopeVersion = 1;
const headerLength = 8;
const saltLength = 16;
const maxTextBytes = 1024 * 1024;
const maxCipherBytes = maxTextBytes + 16;
const maxEncodedCipherLength = (maxCipherBytes + headerLength + saltLength + 16 + 32) * 2 + 4096;
const decryptError = '解密失败，请检查密钥、密文和参数。';

function validateEncoding(encoding) {
  if (encoding !== 'hex' && encoding !== 'base64') {
    throw new Error('请选择 Hex 或 Base64 编码。');
  }
}

function decodeBytes(text, encoding, label, maxLength, allowEmpty = false) {
  if (typeof text !== 'string' || text.length > maxLength) {
    throw new Error(`${label}格式错误或过长。`);
  }
  const clean = text.replace(/[\t\n\r ]/g, '');
  if (!clean && !allowEmpty) {
    throw new Error(`请输入${label}。`);
  }
  if (encoding === 'hex') {
    if (clean.length % 2 !== 0 || /[^a-fA-F0-9]/.test(clean)) {
      throw new Error(`${label}必须是有效的 Hex。`);
    }
    return Buffer.from(clean, 'hex');
  }

  const bytes = Buffer.from(clean, 'base64');
  const canonical = bytes.toString('base64');
  if (clean !== canonical && clean !== canonical.replace(/=+$/, '')) {
    throw new Error(`${label}必须是有效的 Base64。`);
  }
  return bytes;
}

function encodeText(text) {
  if (typeof text !== 'string') {
    throw new Error('请输入文本。');
  }
  if (text.length > maxTextBytes || Buffer.byteLength(text, 'utf8') > maxTextBytes) {
    throw new Error('文本不能超过 1 MiB（UTF-8）。');
  }
  if (!text.isWellFormed()) {
    throw new Error('文本含有无效的 Unicode 字符。');
  }
  return Buffer.from(text, 'utf8');
}

function cipherName(algorithm, keyLength) {
  if (algorithm === 'sm4-cbc') return algorithm;
  return `aes-${keyLength * 8}-${algorithm.slice(4)}`;
}

function validateKey(options, config) {
  const { key, keyFormat, format } = options;
  if (keyFormat === 'password') {
    if (format === 'raw') {
      throw new Error('原始密文模式需要 Hex 或 Base64 密钥。');
    }
    if (typeof key !== 'string' || !key) {
      throw new Error('请输入密码。');
    }
    if (key.length > 4096 || Buffer.byteLength(key, 'utf8') > 4096 || !key.isWellFormed()) {
      throw new Error('密码必须是有效的 Unicode 文本，且不能超过 4096 字节。');
    }
    return { password: key, length: config.passwordKeyLength };
  }

  if (keyFormat !== 'hex' && keyFormat !== 'base64') {
    throw new Error('请选择密码、Hex 或 Base64 密钥。');
  }
  const bytes = decodeBytes(key ?? '', keyFormat, '密钥', 128);
  if (!config.keyLengths.includes(bytes.length)) {
    throw new Error(`密钥长度必须为 ${config.keyLengths.join('、')} 字节。`);
  }
  return { bytes, length: bytes.length };
}

function decodeHexField(value, label, length) {
  const bytes = decodeBytes(value ?? '', 'hex', label, 128);
  if (bytes.length !== length) {
    throw new Error(`${label}长度必须为 ${length} 字节（${length * 2} 位 Hex）。`);
  }
  return bytes;
}

function signCiphertext(key, prefix, ciphertext) {
  const macKey = hkdfSync('sha256', key, Buffer.alloc(0), 'CMST v1 CBC authentication', 32);
  return createHmac('sha256', macKey).update(prefix).update(ciphertext).digest();
}

function encryptBytes(context, input, key, iv, prefix) {
  const { name, config } = context;
  let ciphertext;
  if (name === 'sm4-cbc') {
    ciphertext = Buffer.from(sm4.encrypt(input, key, { mode: 'cbc', iv, padding: 'pkcs#7', output: 'array' }));
  } else {
    const cipher = createCipheriv(name, key, iv, config.gcm ? { authTagLength: config.tagLength } : undefined);
    if (config.gcm && prefix) cipher.setAAD(prefix);
    ciphertext = Buffer.concat([cipher.update(input), cipher.final()]);
    if (config.gcm) return { ciphertext, tag: cipher.getAuthTag() };
  }
  if (prefix) return { ciphertext, tag: signCiphertext(key, prefix, ciphertext) };
  return { ciphertext };
}

function decryptSm4(ciphertext, key, iv) {
  const padded = Buffer.from(sm4.decrypt(ciphertext, key, { mode: 'cbc', iv, padding: 'none', output: 'array' }));
  const paddingLength = padded.at(-1);
  if (paddingLength < 1 || paddingLength > blockSize ||
      !timingSafeEqual(padded.subarray(-paddingLength), Buffer.alloc(paddingLength, paddingLength))) {
    throw new Error(decryptError);
  }
  return padded.subarray(0, padded.length - paddingLength);
}

function decryptBytes(context, ciphertext, key, iv, tag, prefix) {
  const { name, config } = context;
  if (!config.gcm && (ciphertext.length === 0 || ciphertext.length % blockSize !== 0)) {
    throw new Error(decryptError);
  }
  if (!config.gcm && prefix && !timingSafeEqual(tag, signCiphertext(key, prefix, ciphertext))) {
    throw new Error(decryptError);
  }

  let plaintext;
  try {
    if (name === 'sm4-cbc') {
      plaintext = decryptSm4(ciphertext, key, iv);
    } else {
      const decipher = createDecipheriv(name, key, iv, config.gcm ? { authTagLength: config.tagLength } : undefined);
      if (config.gcm) {
        decipher.setAuthTag(tag);
        if (prefix) decipher.setAAD(prefix);
      }
      plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    }
  } catch {
    throw new Error(decryptError);
  }
  if (plaintext.length > maxTextBytes) {
    throw new Error('解密结果超过 1 MiB（UTF-8）。');
  }
  try {
    return utf8.decode(plaintext);
  } catch {
    throw new Error('解密结果不是有效的 UTF-8 文本，请检查密钥和密文。');
  }
}

async function encryptEnvelope(context, options) {
  const { config, keyInfo } = context;
  const plaintext = encodeText(options.input);
  const keyMode = keyInfo.password ? 1 : 0;
  const salt = keyMode ? randomBytes(saltLength) : Buffer.alloc(0);
  const iv = randomBytes(config.ivLength);
  const header = Buffer.concat([envelopeMagic, Buffer.from([envelopeVersion, config.id, keyMode, keyInfo.length])]);
  const prefix = Buffer.concat([header, salt, iv]);
  const key = keyInfo.bytes ?? await derivePasswordKey(keyInfo.password, salt, keyInfo.length, passwordParameters);
  try {
    const { ciphertext, tag } = encryptBytes(context, plaintext, key, iv, prefix);
    return { output: Buffer.concat([prefix, ciphertext, tag]).toString(options.encoding) };
  } finally {
    key.fill(0);
  }
}

async function decryptEnvelope(context, options) {
  const { config, keyInfo } = context;
  const envelope = decodeBytes(options.input, options.encoding, '密文', maxEncodedCipherLength);
  if (envelope.length < headerLength || !envelope.subarray(0, 4).equals(envelopeMagic)) {
    throw new Error('密文包格式无效，请检查编码或切换到原始密文模式。');
  }
  if (envelope[4] !== envelopeVersion) {
    throw new Error('当前版本无法解析该密文包。');
  }
  if (envelope[5] !== config.id) {
    throw new Error('所选算法与密文包的算法不一致。');
  }
  const keyMode = keyInfo.password ? 1 : 0;
  if (envelope[6] !== keyMode) {
    throw new Error('所选密钥类型与密文包不一致。');
  }
  if (envelope[7] !== keyInfo.length) {
    throw new Error('密钥长度与密文包不一致。');
  }

  const ivStart = headerLength + (keyMode ? saltLength : 0);
  const ciphertextStart = ivStart + config.ivLength;
  const tagStart = envelope.length - config.tagLength;
  if (tagStart < ciphertextStart || tagStart - ciphertextStart > maxCipherBytes) {
    throw new Error('密文包长度无效。');
  }
  const prefix = envelope.subarray(0, ciphertextStart);
  const salt = prefix.subarray(headerLength, ivStart);
  const iv = prefix.subarray(ivStart);
  const ciphertext = envelope.subarray(ciphertextStart, tagStart);
  const tag = envelope.subarray(tagStart);
  const key = keyInfo.bytes ?? await derivePasswordKey(keyInfo.password, salt, keyInfo.length, passwordParameters);
  try {
    return { output: decryptBytes(context, ciphertext, key, iv, tag, prefix) };
  } finally {
    key.fill(0);
  }
}

function transformRaw(context, options) {
  const { config, keyInfo } = context;
  const key = keyInfo.bytes;
  try {
    if (options.operation === 'encrypt') {
      const plaintext = encodeText(options.input);
      const iv = options.iv == null || options.iv === ''
        ? randomBytes(config.ivLength)
        : decodeHexField(options.iv, 'IV', config.ivLength);
      const { ciphertext, tag } = encryptBytes(context, plaintext, key, iv);
      const result = { output: ciphertext.toString(options.encoding), iv: iv.toString('hex') };
      if (tag) result.tag = tag.toString('hex');
      return result;
    }

    const iv = decodeHexField(options.iv, 'IV', config.ivLength);
    const ciphertext = decodeBytes(options.input, options.encoding, '密文', maxEncodedCipherLength, config.gcm);
    if (ciphertext.length > maxCipherBytes) {
      throw new Error('密文超出长度限制。');
    }
    const tag = config.gcm ? decodeHexField(options.tag, '认证标签', config.tagLength) : undefined;
    return { output: decryptBytes(context, ciphertext, key, iv, tag) };
  } finally {
    key.fill(0);
  }
}

function runSm3({ operation, input, encoding = 'hex', expected }) {
  if (operation !== 'hash' && operation !== 'verify') {
    throw new Error('SM3 支持计算和校验摘要。');
  }
  validateEncoding(encoding);
  const digest = Buffer.from(sm3(encodeText(input)), 'hex');
  const result = { output: digest.toString(encoding) };
  if (operation === 'verify') {
    const expectedBytes = decodeBytes(expected ?? '', encoding, '待校验摘要', 128);
    if (expectedBytes.length !== digest.length) {
      throw new Error('SM3 摘要长度必须为 32 字节。');
    }
    result.verified = timingSafeEqual(digest, expectedBytes);
  }
  return result;
}

async function runCrypto(options) {
  if (!options || typeof options !== 'object') {
    throw new Error('请求参数无效。');
  }
  const {
    algorithm,
    operation,
    format = 'envelope',
    encoding = 'base64',
    keyFormat = 'password',
  } = options;
  if (algorithm === 'sm3') return runSm3(options);
  if (typeof algorithm !== 'string' || !Object.hasOwn(ciphers, algorithm)) {
    throw new Error('请选择受支持的算法。');
  }
  if (operation !== 'encrypt' && operation !== 'decrypt') {
    throw new Error('请选择加密或解密。');
  }
  if (format !== 'envelope' && format !== 'raw') {
    throw new Error('请选择密文包或原始密文。');
  }
  validateEncoding(encoding);
  const parameters = { ...options, format, encoding, keyFormat };
  const config = ciphers[algorithm];
  const keyInfo = validateKey(parameters, config);
  const name = cipherName(algorithm, keyInfo.length);
  if (name !== 'sm4-cbc' && !supportedCiphers.has(name)) {
    throw new Error('当前运行环境不支持该算法。');
  }
  const context = { name, config, keyInfo };
  if (format === 'raw') return transformRaw(context, parameters);
  if (operation === 'encrypt') return encryptEnvelope(context, parameters);
  return decryptEnvelope(context, parameters);
}

module.exports = { runCrypto };
