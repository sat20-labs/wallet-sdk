import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'crypto';
import { AccountBackup, AccountLocator, EncryptedAccountBackup } from './types';
import { normalizeAccountBackup } from './validation';

const BACKUP_KEY_DOMAIN = 'sat20-wallet-account-backup-key-v1';
const BACKUP_AAD_DOMAIN = 'sat20-wallet-account-backup-aad-v1';

function canonicalBackupBytes(backup: AccountBackup): Buffer {
  return Buffer.from(JSON.stringify(normalizeAccountBackup(backup)), 'utf8');
}

function backupAad(locator: AccountLocator): Buffer {
  return Buffer.from(
    [BACKUP_AAD_DOMAIN, locator.version, locator.accountId, locator.packageId, locator.recoveryMode].join('|'),
    'utf8'
  );
}

export function deriveAccountBackupKey(accountSecret: Buffer, locator: AccountLocator): Buffer {
  if (!Buffer.isBuffer(accountSecret) || accountSecret.length !== 32) {
    throw new Error('account secret must be exactly 32 bytes');
  }
  return createHmac('sha256', accountSecret)
    .update(BACKUP_KEY_DOMAIN, 'utf8')
    .update('\0', 'utf8')
    .update(locator.accountId, 'utf8')
    .update('\0', 'utf8')
    .update(locator.packageId, 'utf8')
    .digest();
}

export function hashAccountBackup(backup: AccountBackup): string {
  const plaintext = canonicalBackupBytes(backup);
  try {
    return createHash('sha256').update(plaintext).digest('hex');
  } finally {
    plaintext.fill(0);
  }
}

export function encryptAccountBackup(
  accountSecret: Buffer,
  locator: AccountLocator,
  backup: AccountBackup
): EncryptedAccountBackup {
  const key = deriveAccountBackupKey(accountSecret, locator);
  const plaintext = canonicalBackupBytes(backup);
  try {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(backupAad(locator));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      algorithm: 'aes-256-gcm',
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      ciphertext: ciphertext.toString('base64')
    };
  } finally {
    key.fill(0);
    plaintext.fill(0);
  }
}

export function decryptAccountBackup(
  accountSecret: Buffer,
  locator: AccountLocator,
  encrypted: EncryptedAccountBackup
): AccountBackup {
  if (!encrypted || encrypted.algorithm !== 'aes-256-gcm') {
    throw new Error('unsupported account backup encryption');
  }

  const key = deriveAccountBackupKey(accountSecret, locator);
  let plaintext: Buffer = null;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(encrypted.iv, 'base64'));
    decipher.setAAD(backupAad(locator));
    decipher.setAuthTag(Buffer.from(encrypted.authTag, 'base64'));
    plaintext = Buffer.concat([
      decipher.update(Buffer.from(encrypted.ciphertext, 'base64')),
      decipher.final()
    ]);
    return normalizeAccountBackup(JSON.parse(plaintext.toString('utf8')) as AccountBackup);
  } finally {
    key.fill(0);
    if (plaintext) plaintext.fill(0);
  }
}
