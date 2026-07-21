import { randomBytes as nodeRandomBytes } from 'crypto';
import { decryptAccountBackup, encryptAccountBackup, hashAccountBackup } from './crypto';
import { DkvsAccountRepository } from './repository';
import { RandomSource, combineAccountSecret, createPackageId, splitAccountSecret } from './shamir';
import {
  AccountBackup,
  AccountEnvelope,
  AccountRecoveryPackage,
  AccountRecoverySummary,
  CreateAccountPackageOptions,
  NewDeviceRecoveryOptions,
  NewDeviceRecoveryResult,
  RecoveryManifest,
  RecoveryShare
} from './types';
import { normalizeAccountBackup } from './validation';

function assertLocatorMatchesShares(envelope: AccountEnvelope, shares: RecoveryShare[]) {
  if (!shares || shares.length < 2) {
    throw new Error('at least two recovery shares are required');
  }
  const expectedTotal = envelope.locator.recoveryMode === '2of2' ? 2 : 3;
  for (const share of shares) {
    if (share.packageId !== envelope.locator.packageId) {
      throw new Error('recovery share packageId does not match the account locator');
    }
    if (share.total !== expectedTotal) {
      throw new Error('recovery share policy does not match the account locator');
    }
  }
}

function summarizeBackup(envelope: AccountEnvelope, backup: AccountBackup): AccountRecoverySummary {
  return {
    accountId: envelope.locator.accountId,
    packageId: envelope.locator.packageId,
    recoveryMode: envelope.locator.recoveryMode,
    wallets: backup.wallets.map((wallet) => ({
      name: wallet.name,
      accountCount: wallet.accountCount,
      subAccountNames: wallet.subAccounts.map((account) => account.name)
    }))
  };
}

export class AccountManager {
  private readonly repository?: DkvsAccountRepository;
  private readonly randomSource: RandomSource;

  constructor(repository?: DkvsAccountRepository, randomSource: RandomSource = nodeRandomBytes) {
    this.repository = repository;
    this.randomSource = randomSource;
  }

  createRecoveryPackage(options: CreateAccountPackageOptions): AccountRecoveryPackage {
    if (!options || !options.accountId || !/^[a-z0-9._-]+$/.test(options.accountId)) {
      throw new Error('invalid accountId');
    }

    const backup = normalizeAccountBackup(options.backup);
    const accountSecret = this.randomSource(32);
    if (!Buffer.isBuffer(accountSecret) || accountSecret.length !== 32) {
      throw new Error('random source returned an invalid account secret');
    }

    try {
      const packageId = createPackageId(this.randomSource);
      const locator = {
        version: 1 as const,
        accountId: options.accountId,
        packageId,
        recoveryMode: options.recoveryMode
      };
      const shares = splitAccountSecret(accountSecret, packageId, options.recoveryMode, this.randomSource);
      const backupHash = hashAccountBackup(backup);
      const envelope: AccountEnvelope = {
        version: 1,
        locator,
        encryptedBackup: encryptAccountBackup(accountSecret, locator, backup),
        backupHash
      };
      const manifest: RecoveryManifest = {
        version: 1,
        locator,
        threshold: 2,
        total: options.recoveryMode === '2of2' ? 2 : 3,
        backupHash,
        createdAt: Date.now()
      };

      return {
        envelope,
        manifest,
        userShare: shares.find((share) => share.role === 'user'),
        dkvsShare: shares.find((share) => share.role === 'dkvs'),
        guardianShare: shares.find((share) => share.role === 'guardian')
      };
    } finally {
      accountSecret.fill(0);
    }
  }

  async publishRecoveryPackage(recoveryPackage: AccountRecoveryPackage): Promise<void> {
    if (!this.repository) {
      throw new Error('a DKVS account repository is required');
    }
    if (recoveryPackage.envelope.locator.accountId !== this.repository.accountId) {
      throw new Error('recovery package does not belong to the repository account');
    }
    await this.repository.saveEnvelope(recoveryPackage.envelope);
    await this.repository.saveManifest(recoveryPackage.manifest);
  }

  recoverAccount(envelope: AccountEnvelope, shares: RecoveryShare[]): AccountBackup {
    if (!envelope || envelope.version !== 1) {
      throw new Error('invalid account envelope');
    }
    assertLocatorMatchesShares(envelope, shares);
    const accountSecret = combineAccountSecret(shares);
    try {
      const backup = decryptAccountBackup(accountSecret, envelope.locator, envelope.encryptedBackup);
      if (hashAccountBackup(backup) !== envelope.backupHash) {
        throw new Error('account backup hash mismatch');
      }
      return backup;
    } finally {
      accountSecret.fill(0);
    }
  }

  async recoverAccountFromDkvs(locator: AccountEnvelope['locator'], shares: RecoveryShare[]): Promise<AccountBackup> {
    if (!this.repository) {
      throw new Error('a DKVS account repository is required');
    }
    if (locator.accountId !== this.repository.accountId) {
      throw new Error('account locator does not belong to the repository account');
    }
    const envelope = await this.repository.getEnvelope();
    if (!envelope) {
      throw new Error('account envelope was not found in DKVS');
    }
    if (
      envelope.locator.packageId !== locator.packageId ||
      envelope.locator.recoveryMode !== locator.recoveryMode
    ) {
      throw new Error('account locator does not match the current DKVS envelope');
    }
    return this.recoverAccount(envelope, shares);
  }

  async restoreOnNewDevice(options: NewDeviceRecoveryOptions): Promise<NewDeviceRecoveryResult> {
    const backup = await this.recoverAccountFromDkvs(options.locator, options.shares);
    const envelope = await this.repository.getEnvelope();
    const summary = summarizeBackup(envelope, backup);
    const confirmed = await options.confirm(summary);
    if (!confirmed) {
      throw new Error('new-device recovery was not confirmed');
    }
    await options.persist(backup);
    return {
      backup,
      summary,
      rehearsalCompleted: true
    };
  }
}
