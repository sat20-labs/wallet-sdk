import { createHash, randomBytes as nodeRandomBytes } from 'crypto';
import * as secrets from 'secrets.js-grempe';
import { RecoveryMode, RecoveryShare, RecoveryShareRole } from './types';

export type RandomSource = (size: number) => Buffer;

const SHARE_PREFIX = 'sat20-share-v1:';
const ACCOUNT_SECRET_SIZE = 32;
const PACKAGE_ID_BYTES = 16;
const SHAMIR_FIELD_BITS = 8;
const SHAMIR_THRESHOLD = 2;
const SHAMIR_PAD_BITS = ACCOUNT_SECRET_SIZE * 8;

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

function validateRecoveryShare(share: RecoveryShare): string {
  if (
    !share ||
    share.version !== 1 ||
    share.threshold !== SHAMIR_THRESHOLD ||
    (share.total !== 2 && share.total !== 3) ||
    !/^[0-9a-f]{32}$/.test(share.packageId) ||
    !Number.isInteger(share.index) ||
    share.index < 1 ||
    share.index > share.total ||
    share.role !== expectedRole(share.total, share.index) ||
    !/^[0-9a-f]{16}$/.test(share.checksum) ||
    !/^[0-9a-f]+$/.test(share.data)
  ) {
    throw new Error('invalid recovery share payload');
  }

  const { checksum, ...withoutChecksum } = share;
  if (computeShareChecksum(withoutChecksum) !== checksum) {
    throw new Error('invalid recovery share checksum');
  }

  let components: { bits: number; id: number; data: string };
  try {
    components = secrets.extractShareComponents(share.data);
  } catch (error) {
    throw new Error('invalid Shamir share encoding');
  }
  if (
    components.bits !== SHAMIR_FIELD_BITS ||
    components.id !== share.index ||
    typeof components.data !== 'string' ||
    components.data.length === 0
  ) {
    throw new Error('recovery share metadata does not match the Shamir share');
  }

  return share.data;
}

export function createPackageId(randomSource: RandomSource = nodeRandomBytes): string {
  const bytes = randomSource(PACKAGE_ID_BYTES);
  if (!Buffer.isBuffer(bytes) || bytes.length !== PACKAGE_ID_BYTES) {
    throw new Error('random source returned an invalid package id');
  }
  return bytes.toString('hex');
}

/**
 * Splits the account secret through secrets.js-grempe 2.0.0.
 *
 * The dependency is the established browser/Node secrets.js implementation
 * that was included in the Cure53 PrivEOS audit. This module only adds
 * package binding, roles and checksums around its canonical public shares.
 */
export function splitAccountSecret(secret: Buffer, packageId: string, mode: RecoveryMode): RecoveryShare[] {
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
  const publicShares = secrets.share(secret.toString('hex'), total, SHAMIR_THRESHOLD, SHAMIR_PAD_BITS);
  if (!Array.isArray(publicShares) || publicShares.length !== total) {
    throw new Error('Shamir provider returned an invalid number of shares');
  }

  return publicShares.map((data, offset) => {
    const index = offset + 1;
    const components = secrets.extractShareComponents(data);
    if (components.bits !== SHAMIR_FIELD_BITS || components.id !== index) {
      throw new Error('Shamir provider returned an unexpected share id');
    }
    const unsignedShare: Omit<RecoveryShare, 'checksum'> = {
      version: 1,
      packageId,
      threshold: SHAMIR_THRESHOLD,
      total,
      index,
      role: roles[offset],
      data
    };
    return {
      ...unsignedShare,
      checksum: computeShareChecksum(unsignedShare)
    };
  });
}

export function combineAccountSecret(shares: RecoveryShare[]): Buffer {
  if (!Array.isArray(shares) || shares.length < SHAMIR_THRESHOLD) {
    throw new Error('at least two recovery shares are required');
  }

  const reference = shares[0];
  const indexes = new Set<number>();
  const publicShares: string[] = [];
  for (const share of shares) {
    const publicShare = validateRecoveryShare(share);
    if (share.packageId !== reference.packageId) {
      throw new Error('recovery shares belong to different packages');
    }
    if (share.threshold !== reference.threshold || share.total !== reference.total) {
      throw new Error('incompatible recovery share policy');
    }
    if (indexes.has(share.index)) {
      throw new Error('recovery share indexes must be unique');
    }
    indexes.add(share.index);
    publicShares.push(publicShare);
  }

  let secretHex: string;
  try {
    secretHex = secrets.combine(publicShares.slice(0, SHAMIR_THRESHOLD));
  } catch (error) {
    throw new Error('failed to combine recovery shares');
  }
  if (!/^[0-9a-f]{64}$/.test(secretHex)) {
    throw new Error('combined account secret has an invalid length or encoding');
  }
  return Buffer.from(secretHex, 'hex');
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
