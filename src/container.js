import fs from 'node:fs/promises';
import { isLegacyMrbak, LegacyMrbakContainer } from './mrbak-legacy.js';
import { isReflectXMrbak, ReflectXMrbakContainer } from './mrbak-x.js';
import { Fat32Volume } from './fat32.js';

/**
 * Open a Macrium Reflect .mrbak / .mrbakx (or .mrimg / .mrimgx) file,
 * automatically detecting Reflect X vs Legacy v7/v8 format and initializing
 * the underlying FAT32 virtual drive when present.
 */
export async function openMrbak(filePath, options = {}) {
  const stat = await fs.stat(filePath).catch((err) => {
    throw new Error(`Cannot access "${filePath}": ${err.message}`);
  });
  if (!stat.isFile()) {
    throw new Error(`Not a file: ${filePath}`);
  }

  let container;
  if (await isReflectXMrbak(filePath)) {
    container = new ReflectXMrbakContainer();
  } else if (await isLegacyMrbak(filePath)) {
    container = new LegacyMrbakContainer();
  } else {
    throw new Error(
      `Unrecognized file format: "${filePath}" (expected Macrium Reflect .mrbak/.mrbakx/.mrimg/.mrimgx footer)`
    );
  }

  await container.open(filePath, options);

  const partIndex = options.partition ?? 0;
  let fat32 = null;
  let fsError = null;
  try {
    const volStream = container.getVolumeStream(partIndex);
    const fs = new Fat32Volume(volStream);
    await fs.init();
    fat32 = fs;
  } catch (err) {
    fsError = err.message;
  }

  return {
    container,
    fat32,
    fsError,
    async close() {
      await container.close();
    },
  };
}
