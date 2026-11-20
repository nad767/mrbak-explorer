import crypto from 'node:crypto';

/**
 * Macrium Reflect X encryption helpers (PBKDF2-HMAC-SHA256, HMAC validation,
 * ESSIV-style IV generation, and AES-CBC block decryption).
 */

const AES_KEY_SIZES = {
  'aes-128': { keyLen: 16, cipher: 'aes-128-cbc' },
  'aes-192': { keyLen: 24, cipher: 'aes-192-cbc' },
  'aes-256': { keyLen: 32, cipher: 'aes-256-cbc' },
};

/**
 * Derive the AES key from the user password and verify its HMAC against the
 * value stored in the $JSON `_encryption` object.
 * @param {object} jsonRoot Parsed $JSON metadata
 * @param {string} password Plaintext password
 * @returns {{ key: Buffer, keyHash: Buffer, cipher: string, imageIdBytes: Buffer }}
 */
export function initReflectXCrypto(jsonRoot, password) {
  const enc = jsonRoot?._encryption;
  const hdr = jsonRoot?._header;
  if (!enc?.enable) {
    throw new Error('Archive is not encrypted');
  }
  if (!password) {
    throw new Error('This archive is encrypted. Provide a password with --password.');
  }

  const aesType = (enc.aes_type || 'aes-256').toLowerCase();
  const spec = AES_KEY_SIZES[aesType];
  if (!spec) {
    throw new Error(`Unsupported AES type: ${enc.aes_type}`);
  }

  const imageIdHex = hdr?.imageid || '';
  if (!/^[0-9a-fA-F]{16}$/.test(imageIdHex)) {
    throw new Error(`Invalid imageid for key derivation: "${imageIdHex}"`);
  }
  const imageIdBytes = Buffer.from(imageIdHex, 'hex');
  const salt = crypto.createHash('sha256').update(imageIdBytes).digest();
  const iterations = Number(enc.key_iterations) || 600000;

  const key = crypto.pbkdf2Sync(
    Buffer.from(password, 'utf8'),
    salt,
    iterations,
    spec.keyLen,
    'sha256'
  );

  if (enc.hmac) {
    const computedHmac = crypto.createHmac('sha256', key).digest('hex');
    if (computedHmac.toLowerCase() !== String(enc.hmac).toLowerCase()) {
      throw new Error('Incorrect password (HMAC verification failed)');
    }
  }

  const keyHash = crypto.createHash('sha256').update(key).digest();
  return {
    key,
    keyHash,
    cipher: spec.cipher,
    imageIdBytes,
  };
}

/**
 * Compute the 16-byte ESSIV initialization vector for a Reflect X block.
 * @param {{ keyHash: Buffer, imageIdBytes: Buffer }} ctx
 * @param {number} diskNumber
 * @param {number} partitionNumber
 * @param {number} blockIndex
 * @returns {Buffer}
 */
export function computeReflectXIv(ctx, diskNumber, partitionNumber, blockIndex) {
  const data = Buffer.alloc(16);
  ctx.imageIdBytes.copy(data, 0, 0, 8);
  data.writeUInt16LE(diskNumber & 0xffff, 8);
  data.writeUInt16LE(partitionNumber & 0xffff, 10);
  data.writeInt32LE(blockIndex | 0, 12);

  const ecb = crypto.createCipheriv('aes-256-ecb', ctx.keyHash, null);
  ecb.setAutoPadding(false);
  return Buffer.concat([ecb.update(data), ecb.final()]);
}

/**
 * Decrypt a single AES-CBC encrypted block using ESSIV IV.
 * @param {{ key: Buffer, keyHash: Buffer, cipher: string, imageIdBytes: Buffer }} ctx
 * @param {Uint8Array} encrypted
 * @param {number} diskNumber
 * @param {number} partitionNumber
 * @param {number} blockIndex
 * @returns {Buffer}
 */
export function decryptReflectXBlock(ctx, encrypted, diskNumber, partitionNumber, blockIndex) {
  const iv = computeReflectXIv(ctx, diskNumber, partitionNumber, blockIndex);
  const decipher = crypto.createDecipheriv(ctx.cipher, ctx.key, iv);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}
