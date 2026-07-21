import { createHash, randomBytes as nodeRandomBytes } from 'crypto';
import { RecoveryMode, RecoveryShare, RecoveryShareRole } from './types';

export type RandomSource = (size: number) => Buffer;

const SHARE_PREFIX = 'sat20-share-v1:';
const ACCOUNT_SECRET_SIZE = 32;
const PACKAGE_ID_BYTES = 16;

function gfMultiply(a: number, b: number): number {
  let left = a & 0xff;
  let right = b & 0xff;
  let product = 0;

  for (let bit = 0; bit < 8; bit++) {
    if ((right & 1) !== 0) product ^= left;
    const carry = left & 0x80;
    left = (left << 1) & 0xff;
    if (carry !== 0) left ^= 0x1b;
    right >>= 1;
  }

  return product & 0xff;
}

function gfPower(value: number, exponent: number): number {
  let result = 1;
  let base = value & 0xff;
  let power = exponent;
  while (power > 0) {
    if ((power & 1) === 1) result = gfMultiply(result, base);
    base = gfMultiply(base, base);
    power >>= 1;
  }
  return result;
}

function gfInverse(value: number): number {
  if (value === 0) throw new Error('cannot invert zero in GF(256)');
  return gfPower(value, 254);
}

function gfDivide(numerator: number, denominator: number): number {
  if (numerator === 0) return 0;
  return gfMultiply(numerator, gfInverse(denominator));
}

function base64UrlEncode(value: Buffer): string {
  return value
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(value: string): Buffer {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const paddingLength = (4 - (normalized.length % 4)) % 4;
  return Buffer.from(normalized + '='.repeat(paddingLength), 'base64');
}

function shareChecksumInput(share: Omit<RecoveryShare, 'checksum'>): string {
  return [
    share.version,
    share.packageId,
    share.threshold,
    share.total,
    share.index,
    share.role,
    share.data
  ].join('|');
}

function computeShareChecksum(share: Omit<RecoveryShare, 'checksum'>): string {
  return createHash('sha256').update(shareChecksumInput(share), 'utf8').digest('hex').slice(0, 16);
}

function expectedRole(total: 2 | 3, index: number): RecoveryShareRole {
  const roles: RecoveryShareRole[] = total === 2 ? ['user', 'dkvs'] : ['user', 'dkvs', 'guardian'];
  return roles[index - 1];
}

function validateRecoveryShare(share: RecoveryShare): Buffer {
  if (
    !share ||
    share.version !== 1 ||
    share.threshold !== 2 ||
    (share.total !== 2 && share.total !== 3) ||
    !/^[0-9a-f]{32}$/.test(share.packageId) ||
    !Number.isInteger(share.index) ||
    share.index < 1 ||
    share.index > share.total ||
    share.role !== expectedRole(share.total, share.index) ||
    !/^[0-9a-f]{16}$/.test(share.checksum)
  ) {
    throw new Error('invalid recovery share payload');
  }

  const { checksum, ...withoutChecksum } = share;
  if (computeShareChecksum(withoutChecksum) !== checksum) {
    throw new Error('invalid recovery share checksum');
  }

  const shareBytes = Buffer.from(share.data, 'base64');
  if (
    shareBytes.length !== ACCOUNT_SECRET_SIZE + 1 ||
    shareBytes[0] !== share.index ||
    shareBytes.toString('base64') !== share.data
  ) {
    throw new Error('invalid encoded recovery share data');
  }
  return shareBytes;
}

export function createPackageId(randomSource: RandomSource = nodeRandomBytes): string {
  const bytes = randomSource(PACKAGE_ID_BYTES);
  if (!Buffer.isBuffer(bytes) || bytes.length !== PACKAGE_ID_BYTES) {
    throw new Error('random source returned an invalid package id');
  }
  return bytes.toString('hex');
}

export function splitAccountSecret(
  secret: Buffer,
  packageId: string,
  mode: RecoveryMode,
  randomSource: RandomSource = nodeRandomBytes
): RecoveryShare[] {
  if (!Buffer.isBuffer(secret) || secret.length !== ACCOUNT_SECRET_SIZE) {
    throw new Error(`account secret must be exactly ${ACCOUNT_SECRET_SIZE} bytes`);
  }
  if (!/^[0-9a-f]{32}$/.test(packageId)) {
    throw new Error('packageId must be 16 random bytes encoded as lowercase hex');
  }
  if (mode !== '2of2' && mode !== '2of3') {
    throw new Error('unsupported recovery mode');
  }

  const total: 2 | 3 = mode === '2of2' ? 2 : 3;
  const roles: RecoveryShareRole[] = mode === '2of2' ? ['user', 'dkvs'] : ['user', 'dkvs', 'guardian'];
  const coefficient = randomSource(secret.length);
  if (!Buffer.isBuffer(coefficient) || coefficient.length !== secret.length) {
    throw new Error('random source returned an invalid coefficient');
  }

  try {
    return roles.map((role, offset) => {
      const index = offset + 1;
      const shareBytes = Buffer.alloc(secret.length + 1);
      shareBytes[0] = index;
      for (let byteIndex = 0; byteIndex < secret.length; byteIndex++) {
        shareBytes[byteIndex + 1] = secret[byteIndex] ^ gfMultiply(coefficient[byteIndex], index);
      }

      const unsignedShare: Omit<RecoveryShare, 'checksum'> = {
        version: 1,
        packageId,
        threshold: 2,
        total,
        index,
        role,
        data: shareBytes.toString('base64')
      };

      return {
        ...unsignedShare,
        checksum: computeShareChecksum(unsignedShare)
      };
    });
  } finally {
    coefficient.fill(0);
  }
}

export function combineAccountSecret(shares: RecoveryShare[]): Buffer {
  if (!Array.isArray(shares) || shares.length < 2) {
    throw new Error('at least two recovery shares are required');
  }

  const parsed = shares.map((share) => ({ share, bytes: validateRecoveryShare(share) }));
  const reference = parsed[0].share;
  const indexes = new Set<number>();
  for (const item of parsed) {
    if (item.share.packageId !== reference.packageId) {
      throw new Error('recovery shares belong to different packages');
    }
    if (item.share.threshold !== reference.threshold || item.share.total !== reference.total) {
      throw new Error('incompatible recovery share policy');
    }
    if (indexes.has(item.share.index)) {
      throw new Error('recovery share indexes must be unique');
    }
    indexes.add(item.share.index);
  }

  const first = parsed[0];
  const second = parsed[1];
  const x1 = first.share.index;
  const x2 = second.share.index;
  const denominator = x1 ^ x2;
  if (denominator === 0) throw new Error('invalid recovery share indexes');

  const lambda1 = gfDivide(x2, denominator);
  const lambda2 = gfDivide(x1, denominator);
  const secret = Buffer.alloc(ACCOUNT_SECRET_SIZE);

  for (let byteIndex = 1; byteIndex < first.bytes.length; byteIndex++) {
    secret[byteIndex - 1] =
      gfMultiply(first.bytes[byteIndex], lambda1) ^ gfMultiply(second.bytes[byteIndex], lambda2);
  }

  return secret;
}

export function encodeRecoveryShare(share: RecoveryShare): string {
  validateRecoveryShare(share);
  return SHARE_PREFIX + base64UrlEncode(Buffer.from(JSON.stringify(share), 'utf8'));
}

export function decodeRecoveryShare(encoded: string): RecoveryShare {
  if (typeof encoded !== 'string' || !encoded.startsWith(SHARE_PREFIX)) {
    throw new Error('invalid recovery share encoding');
  }
  let share: RecoveryShare;
  try {
    const json = base64UrlDecode(encoded.slice(SHARE_PREFIX.length)).toString('utf8');
    share = JSON.parse(json) as RecoveryShare;
  } catch (error) {
    throw new Error('invalid recovery share encoding');
  }
  validateRecoveryShare(share);
  return share;
}
