import { createHash, randomBytes as nodeRandomBytes } from 'crypto';
import { RecoveryMode, RecoveryShare, RecoveryShareRole } from './types';

export type RandomSource = (size: number) => Buffer;

const SHARE_PREFIX = 'sat20-share-v1:';

function gfMultiply(a: number, b: number): number {
  let left = a & 0xff;
  let right = b & 0xff;
  let product = 0;

  for (let bit = 0; bit < 8; bit++) {
    if ((right & 1) !== 0) {
      product ^= left;
    }
    const carry = left & 0x80;
    left = (left << 1) & 0xff;
    if (carry !== 0) {
      left ^= 0x1b;
    }
    right >>= 1;
  }

  return product & 0xff;
}

function gfPower(value: number, exponent: number): number {
  let result = 1;
  let base = value & 0xff;
  let power = exponent;
  while (power > 0) {
    if ((power & 1) === 1) {
      result = gfMultiply(result, base);
    }
    base = gfMultiply(base, base);
    power >>= 1;
  }
  return result;
}

function gfInverse(value: number): number {
  if (value === 0) {
    throw new Error('cannot invert zero in GF(256)');
  }
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

function assertShareChecksum(share: RecoveryShare) {
  const { checksum, ...withoutChecksum } = share;
  if (computeShareChecksum(withoutChecksum) !== checksum) {
    throw new Error('invalid recovery share checksum');
  }
}

export function createPackageId(randomSource: RandomSource = nodeRandomBytes): string {
  return randomSource(16).toString('hex');
}

export function splitAccountSecret(
  secret: Buffer,
  packageId: string,
  mode: RecoveryMode,
  randomSource: RandomSource = nodeRandomBytes
): RecoveryShare[] {
  if (!Buffer.isBuffer(secret) || secret.length === 0) {
    throw new Error('secret must be a non-empty Buffer');
  }
  if (!packageId || packageId.trim().length === 0) {
    throw new Error('packageId is required');
  }

  const total: 2 | 3 = mode === '2of2' ? 2 : 3;
  const roles: RecoveryShareRole[] = mode === '2of2' ? ['user', 'dkvs'] : ['user', 'dkvs', 'guardian'];
  const coefficient = randomSource(secret.length);
  if (!Buffer.isBuffer(coefficient) || coefficient.length !== secret.length) {
    throw new Error('random source returned an invalid coefficient');
  }

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
}

export function combineAccountSecret(shares: RecoveryShare[]): Buffer {
  if (!Array.isArray(shares) || shares.length < 2) {
    throw new Error('at least two recovery shares are required');
  }

  const selected = shares.slice(0, 2);
  selected.forEach(assertShareChecksum);

  const first = selected[0];
  const second = selected[1];
  if (first.packageId !== second.packageId) {
    throw new Error('recovery shares belong to different packages');
  }
  if (first.threshold !== 2 || second.threshold !== 2 || first.total !== second.total) {
    throw new Error('incompatible recovery share policy');
  }
  if (first.index === second.index) {
    throw new Error('recovery share indexes must be unique');
  }

  const firstBytes = Buffer.from(first.data, 'base64');
  const secondBytes = Buffer.from(second.data, 'base64');
  if (firstBytes.length < 2 || firstBytes.length !== secondBytes.length) {
    throw new Error('incompatible recovery share lengths');
  }
  if (firstBytes[0] !== first.index || secondBytes[0] !== second.index) {
    throw new Error('recovery share index does not match encoded share data');
  }

  const x1 = first.index;
  const x2 = second.index;
  const denominator = x1 ^ x2;
  if (denominator === 0) {
    throw new Error('invalid recovery share indexes');
  }

  const lambda1 = gfDivide(x2, denominator);
  const lambda2 = gfDivide(x1, denominator);
  const secret = Buffer.alloc(firstBytes.length - 1);

  for (let byteIndex = 1; byteIndex < firstBytes.length; byteIndex++) {
    secret[byteIndex - 1] =
      gfMultiply(firstBytes[byteIndex], lambda1) ^ gfMultiply(secondBytes[byteIndex], lambda2);
  }

  return secret;
}

export function encodeRecoveryShare(share: RecoveryShare): string {
  assertShareChecksum(share);
  return SHARE_PREFIX + base64UrlEncode(Buffer.from(JSON.stringify(share), 'utf8'));
}

export function decodeRecoveryShare(encoded: string): RecoveryShare {
  if (typeof encoded !== 'string' || !encoded.startsWith(SHARE_PREFIX)) {
    throw new Error('invalid recovery share encoding');
  }
  const json = base64UrlDecode(encoded.slice(SHARE_PREFIX.length)).toString('utf8');
  const share = JSON.parse(json) as RecoveryShare;
  if (
    !share ||
    share.version !== 1 ||
    share.threshold !== 2 ||
    (share.total !== 2 && share.total !== 3) ||
    !Number.isInteger(share.index) ||
    share.index < 1 ||
    share.index > share.total ||
    !['user', 'dkvs', 'guardian'].includes(share.role)
  ) {
    throw new Error('invalid recovery share payload');
  }
  assertShareChecksum(share);
  return share;
}
