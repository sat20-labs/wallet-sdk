import { randomBytes as nodeRandomBytes } from 'crypto';
import { decryptAccountBackup, encryptAccountBackup, hashAccountEnvelope } from './crypto';
import { DkvsAccountRepository } from './repository';
import { RandomSource, combineAccountSecret, createPackageId, splitAccountSecret } from './shamir';
import {
  AccountBackup,
  AccountEnvelope,
  AccountLocator,
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

function summarizeBackup(locator: AccountLocator, backup: AccountBackup): AccountRecoverySummary {
  return {
    accountId: locator.accountId,
    packageId: locator.packageId,
    recoveryMode: locator.recoveryMode,
    wallets: backup.wallets.map((wallet) => ({
      name: wallet.name,
      accountCount: wallet.accountCount,
      subAccountNames: wallet.subAccounts.map((account) => account.name)
    }))
  };
}

function assertPackageConsistency(recoveryPackage: AccountRecoveryPackage) {
  if (!recoveryPackage || !recoveryPackage.envelope || !recoveryPackage.manifest) {
    throw new Error('invalid recovery package');
  }
  const envelope = recoveryPackage.envelope;
  const manifest = recoveryPackage.manifest;
  if (
    manifest.locator.accountId !== envelope.locator.accountId ||
    manifest.locator.packageId !== envelope.locator.packageId ||
    manifest.locator.recoveryMode !== envelope.locator.recoveryMode ||
    manifest.envelopeHash !== hashAccountEnvelope(envelope)
  ) {
    throw new Error('recovery package envelope and manifest do not match');
  }
}

export class AccountManager {
  private readonly repository?: DkvsAccountRepository;
  private readonly randomSource: RandomSource;

  constructor(repository?: DkvsAccountRepository, randomSource: RandomSource = nodeRandomBytes) {
    this.repository = repository;
    this.randomSource = randomSource;
  }

  createRecoveryPackage(options: CreateAccountPackageOptions): AccountRecoveryPackage {
    if (!options || !/^[0-9a-f]{64}$/.test(options.accountId)) {
      throw new Error('accountId must be a lowercase SHA-256 hex string');
    }
    if (options.recoveryMode !== '2of2' && options.recoveryMode !== '2of3') {
      throw new Error('unsupported recovery mode');
    }

    const backup = normalizeAccountBackup(options.backup);
    const accountSecret = this.randomSource(32);
    if (!Buffer.isBuffer(accountSecret) || accountSecret.length !== 32) {
      throw new Error('random source returned an invalid account secret');
    }

    try {
      const packageId = createPackageId(this.randomSource);
      const locator: AccountLocator = {
        version: 1,
        accountId: options.accountId,
        packageId,
        recoveryMode: options.recoveryMode
      };
      const shares = splitAccountSecret(accountSecret, packageId, options.recoveryMode, this.randomSource);
      const userShare = shares.find((share) => share.role === 'user');
      const dkvsShare = shares.find((share) => share.role === 'dkvs');
      const guardianShare = shares.find((share) => share.role === 'guardian');
      if (!userShare || !dkvsShare || (options.recoveryMode === '2of3' && !guardianShare)) {
        throw new Error('failed to create the required recovery shares');
      }

      const envelope: AccountEnvelope = {
        version: 1,
        locator,
        encryptedBackup: encryptAccountBackup(accountSecret, locator, backup)
      };
      const manifest: RecoveryManifest = {
        version: 1,
        locator,
        threshold: 2,
        total: options.recoveryMode === '2of2' ? 2 : 3,
        envelopeHash: hashAccountEnvelope(envelope),
        createdAt: Date.now()
      };

      return {
        envelope,
        manifest,
        userShare,
        dkvsShare,
        guardianShare
      };
    } finally {
      accountSecret.fill(0);
    }
  }

  async publishRecoveryPackage(recoveryPackage: AccountRecoveryPackage): Promise<void> {
    if (!this.repository) {
      throw new Error('a DKVS account repository is required');
    }
    assertPackageConsistency(recoveryPackage);
    if (recoveryPackage.envelope.locator.accountId !== this.repository.accountId) {
      throw new Error('recovery package does not belong to the repository account');
    }

    // The manifest is written last and acts as the application-level commit marker.
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
      return decryptAccountBackup(accountSecret, envelope.locator, envelope.encryptedBackup);
    } finally {
      accountSecret.fill(0);
    }
  }

  async recoverAccountFromDkvs(locator: AccountLocator, shares: RecoveryShare[]): Promise<AccountBackup> {
    if (!this.repository) {
      throw new Error('a DKVS account repository is required');
    }
    if (locator.accountId !== this.repository.accountId) {
      throw new Error('account locator does not belong to the repository account');
    }

    const [envelope, manifest] = await Promise.all([
      this.repository.getEnvelope(),
      this.repository.getManifest(locator.packageId)
    ]);
    if (!envelope) throw new Error('account envelope was not found in DKVS');
    if (!manifest) throw new Error('recovery manifest was not found in DKVS');
    if (
      envelope.locator.packageId !== locator.packageId ||
      envelope.locator.recoveryMode !== locator.recoveryMode ||
      manifest.locator.accountId !== locator.accountId ||
      manifest.locator.packageId !== locator.packageId ||
      manifest.locator.recoveryMode !== locator.recoveryMode ||
      manifest.envelopeHash !== hashAccountEnvelope(envelope)
    ) {
      throw new Error('account locator, manifest and envelope do not match');
    }

    return this.recoverAccount(envelope, shares);
  }

  async restoreOnNewDevice(options: NewDeviceRecoveryOptions): Promise<NewDeviceRecoveryResult> {
    const backup = await this.recoverAccountFromDkvs(options.locator, options.shares);
    const summary = summarizeBackup(options.locator, backup);
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
