/**
 * QuickLZ 1.31 decompressor (Level 1/2/3, memory-safe).
 *
 * Macrium Reflect v7/v8 .mrbak and .mrimg containers compress blocks with
 * QuickLZ 1.31 at compression level 2 (with RLE and incompressible fallback).
 */

const BITLUT = new Uint8Array([4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0]);

/**
 * Read up to 4 bytes in little-endian unsigned order, zero-padding past end.
 */
function readU32LEPadded(buf, off, end) {
  if (off >= end) return 0;
  const b0 = buf[off];
  const b1 = off + 1 < end ? buf[off + 1] : 0;
  const b2 = off + 2 < end ? buf[off + 2] : 0;
  const b3 = off + 3 < end ? buf[off + 3] : 0;
  return (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0;
}

/**
 * Parse the 3-byte or 9-byte QuickLZ block header.
 * @param {Uint8Array} src
 * @returns {{ flag: number, headerLen: number, compressedSize: number, decompressedSize: number, isCompressed: boolean, isLong: boolean, isLevel0: boolean }}
 */
export function parseQlzHeader(src) {
  if (src.length < 3) {
    throw new Error(`QuickLZ header truncated (${src.length} bytes)`);
  }
  const flag = src[0];
  const isCompressed = (flag & 1) !== 0;
  const isLong = (flag & 2) !== 0;
  const isLevel0 = (flag & 4) !== 0;
  const headerLen = isLong ? 9 : 3;
  if (src.length < headerLen) {
    throw new Error(`QuickLZ long header truncated (${src.length} bytes)`);
  }
  const compressedSize = isLong
    ? ((src[1] | (src[2] << 8) | (src[3] << 16) | (src[4] << 24)) >>> 0)
    : src[1];
  const decompressedSize = isLong
    ? ((src[5] | (src[6] << 8) | (src[7] << 16) | (src[8] << 24)) >>> 0)
    : src[2];
  return {
    flag,
    headerLen,
    compressedSize,
    decompressedSize,
    isCompressed,
    isLong,
    isLevel0,
  };
}

/**
 * Decompress a single QuickLZ 1.31 frame (level != 0).
 * @param {Uint8Array} src
 * @param {Uint8Array} [dest] optional pre-allocated buffer of at least decompressedSize
 * @returns {Uint8Array} slice of decompressed bytes
 */
export function decompressQlz(src, dest) {
  const hdr = parseQlzHeader(src);
  if (hdr.isLevel0) {
    throw new Error('QuickLZ level-0 stream is not supported');
  }
  const { headerLen, compressedSize, decompressedSize, isCompressed } = hdr;
  if (compressedSize < headerLen || src.length < compressedSize) {
    throw new Error(
      `QuickLZ truncated frame: need ${compressedSize} bytes, got ${src.length}`
    );
  }
  if (decompressedSize === 0) {
    return new Uint8Array(0);
  }

  const out = dest && dest.length >= decompressedSize
    ? dest.subarray(0, decompressedSize)
    : new Uint8Array(decompressedSize);

  if (!isCompressed) {
    if (compressedSize < headerLen + decompressedSize) {
      throw new Error('QuickLZ uncompressed block shorter than decompressedSize');
    }
    out.set(src.subarray(headerLen, headerLen + decompressedSize), 0);
    return out;
  }

  let s = headerLen;
  const sEnd = compressedSize;
  let d = 0;
  const guaranteedUncompressed = decompressedSize >= 4 ? decompressedSize - 4 : 0;

  if (d >= guaranteedUncompressed) {
    s += 4;
    while (d < decompressedSize) {
      if (s >= sEnd) {
        throw new Error('QuickLZ short block overrun');
      }
      out[d++] = src[s++];
    }
    return out;
  }

  let cwordVal = 1;
  for (;;) {
    if (cwordVal === 1) {
      if (s + 4 > sEnd) {
        throw new Error('QuickLZ control word past end of compressed block');
      }
      cwordVal = (readU32LEPadded(src, s, sEnd) | 0x80000000) >>> 0;
      s += 4;
    }

    const fetch = readU32LEPadded(src, s, sEnd);

    if ((cwordVal & 1) === 1) {
      cwordVal >>>= 1;

      if ((fetch & 3) === 0) {
        const offset = (fetch & 0xff) >>> 2;
        s += 1;
        if (s > sEnd || offset === 0 || offset > d || 3 > guaranteedUncompressed - d) {
          throw new Error('QuickLZ corrupt short match (type 0)');
        }
        for (let i = 0; i < 3; i++) out[d + i] = out[d - offset + i];
        d += 3;
      } else if ((fetch & 2) === 0) {
        const offset = (fetch & 0xffff) >>> 2;
        s += 2;
        if (s > sEnd || offset === 0 || offset > d || 3 > guaranteedUncompressed - d) {
          throw new Error('QuickLZ corrupt short match (type 1)');
        }
        for (let i = 0; i < 3; i++) out[d + i] = out[d - offset + i];
        d += 3;
      } else if ((fetch & 1) === 0) {
        const offset = (fetch & 0xffff) >>> 6;
        const matchlen = ((fetch >>> 2) & 15) + 3;
        s += 2;
        if (s > sEnd || offset === 0 || offset > d || matchlen > guaranteedUncompressed - d) {
          throw new Error('QuickLZ corrupt match (type 2)');
        }
        for (let i = 0; i < matchlen; i++) out[d + i] = out[d - offset + i];
        d += matchlen;
      } else if ((fetch & 4) === 0) {
        const offset = (fetch & 0xffffff) >>> 8;
        const matchlen = ((fetch >>> 3) & 31) + 3;
        s += 3;
        if (s > sEnd || offset === 0 || offset > d || matchlen > guaranteedUncompressed - d) {
          throw new Error('QuickLZ corrupt match (type 3)');
        }
        for (let i = 0; i < matchlen; i++) out[d + i] = out[d - offset + i];
        d += matchlen;
      } else if ((fetch & 8) === 0) {
        let offset = fetch >>> 15;
        let matchlen;
        if (offset !== 0) {
          matchlen = ((fetch >>> 4) & 2047) + 3;
          s += 4;
        } else {
          if (s + 12 > sEnd) {
            throw new Error('QuickLZ long match past end of compressed block');
          }
          matchlen = readU32LEPadded(src, s + 4, sEnd);
          offset = readU32LEPadded(src, s + 8, sEnd);
          s += 12;
        }
        if (s > sEnd || offset === 0 || offset > d || matchlen > guaranteedUncompressed - d) {
          throw new Error('QuickLZ corrupt match (type 4)');
        }
        for (let i = 0; i < matchlen; i++) out[d + i] = out[d - offset + i];
        d += matchlen;
      } else {
        // RLE sequence
        const rleChar = (fetch >>> 16) & 0xff;
        let matchlen = (fetch >>> 4) & 0xfff;
        if (matchlen !== 0) {
          s += 3;
        } else {
          if (s + 7 > sEnd) {
            throw new Error('QuickLZ long RLE past end of compressed block');
          }
          matchlen = readU32LEPadded(src, s + 3, sEnd);
          s += 7;
        }
        if (s > sEnd || matchlen > guaranteedUncompressed - d) {
          throw new Error('QuickLZ corrupt RLE sequence');
        }
        out.fill(rleChar, d, d + matchlen);
        d += matchlen;
      }
    } else {
      const litCount = BITLUT[cwordVal & 0xf];
      if (d + litCount > decompressedSize || s + litCount > sEnd) {
        throw new Error('QuickLZ literal overrun');
      }
      for (let i = 0; i < litCount; i++) {
        out[d + i] = src[s + i];
      }
      d += litCount;
      s += litCount;
      cwordVal >>>= litCount;

      if (d >= guaranteedUncompressed) {
        while (d < decompressedSize) {
          if (cwordVal === 1) {
            s += 4;
            cwordVal = 0x80000000;
          }
          if (s >= sEnd) {
            throw new Error('QuickLZ trailing literal overrun');
          }
          out[d++] = src[s++];
          cwordVal >>>= 1;
        }
        if (d !== decompressedSize) {
          throw new Error(`QuickLZ size mismatch: got ${d}, expected ${decompressedSize}`);
        }
        return out;
      }
    }
  }
}
