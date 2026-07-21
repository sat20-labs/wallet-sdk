import { createHash } from 'crypto';
import { AccountEnvelope, RecoveryManifest } from './types';

export interface OwnerScopedDkvsClient {
  /** Account ID whose owner key both signs records and pays DKVS fees. */
  readonly accountId: string;
  put(key: string, value: Buffer): Promise<void>;
  get(key: string): Promise<Buffer | null>;
}

function assertAccountId(value: string) {
  if (!value || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error('invalid accountId');
  }
}

function assertPackageId(value: string) {
  if (!value || !/^[0-9a-f]{32}$/.test(value)) {
    throw new Error('invalid packageId');
  }
}

export function accountIdFromPublicKey(publicKey: Buffer): string {
  if (!Buffer.isBuffer(publicKey) || publicKey.length === 0) {
    throw new Error('publicKey must be a non-empty Buffer');
  }
  return createHash('sha256').update(publicKey).digest('hex');
}

export function accountBaseKey(accountId: string): string {
  assertAccountId(accountId);
  return `/personal/${accountId}/account`;
}

export function accountEnvelopeKey(accountId: string): string {
  return `${accountBaseKey(accountId)}/envelope`;
}

export function accountRecoveryManifestKey(accountId: string, packageId: string): string {
  assertPackageId(packageId);
  return `${accountBaseKey(accountId)}/recovery/${packageId}/manifest`;
}

export function accountDkvsShareCapsuleKey(accountId: string, packageId: string): string {
  assertPackageId(packageId);
  return `${accountBaseKey(accountId)}/recovery/${packageId}/share/dkvs`;
}

export function accountRecoveryQuestionsKey(accountId: string, packageId: string): string {
  assertPackageId(packageId);
  return `${accountBaseKey(accountId)}/recovery/${packageId}/questions`;
}

export class DkvsAccountRepository {
  readonly accountId: string;
  private readonly client: OwnerScopedDkvsClient;

  constructor(client: OwnerScopedDkvsClient) {
    if (!client || !client.accountId) {
      throw new Error('an owner-scoped DKVS client is required');
    }
    assertAccountId(client.accountId);
    this.client = client;
    this.accountId = client.accountId;
  }

  async saveEnvelope(envelope: AccountEnvelope): Promise<void> {
    this.assertEnvelopeOwner(envelope);
    await this.client.put(accountEnvelopeKey(this.accountId), Buffer.from(JSON.stringify(envelope), 'utf8'));
  }

  async getEnvelope(): Promise<AccountEnvelope | null> {
    const value = await this.client.get(accountEnvelopeKey(this.accountId));
    if (!value) return null;
    const envelope = JSON.parse(value.toString('utf8')) as AccountEnvelope;
    this.assertEnvelopeOwner(envelope);
    return envelope;
  }

  async saveManifest(manifest: RecoveryManifest): Promise<void> {
    if (manifest.locator.accountId !== this.accountId) {
      throw new Error('manifest accountId does not match owner-scoped DKVS client');
    }
    await this.client.put(
      accountRecoveryManifestKey(this.accountId, manifest.locator.packageId),
      Buffer.from(JSON.stringify(manifest), 'utf8')
    );
  }

  async getManifest(packageId: string): Promise<RecoveryManifest | null> {
    const value = await this.client.get(accountRecoveryManifestKey(this.accountId, packageId));
    if (!value) return null;
    const manifest = JSON.parse(value.toString('utf8')) as RecoveryManifest;
    if (manifest.locator.accountId !== this.accountId || manifest.locator.packageId !== packageId) {
      throw new Error('invalid recovery manifest');
    }
    return manifest;
  }

  async saveDkvsShareCapsule(packageId: string, capsule: Buffer): Promise<void> {
    await this.client.put(accountDkvsShareCapsuleKey(this.accountId, packageId), Buffer.from(capsule));
  }

  async getDkvsShareCapsule(packageId: string): Promise<Buffer | null> {
    const value = await this.client.get(accountDkvsShareCapsuleKey(this.accountId, packageId));
    return value ? Buffer.from(value) : null;
  }

  async saveEncryptedQuestionSet(packageId: string, encryptedQuestionSet: Buffer): Promise<void> {
    await this.client.put(accountRecoveryQuestionsKey(this.accountId, packageId), Buffer.from(encryptedQuestionSet));
  }

  async getEncryptedQuestionSet(packageId: string): Promise<Buffer | null> {
    const value = await this.client.get(accountRecoveryQuestionsKey(this.accountId, packageId));
    return value ? Buffer.from(value) : null;
  }

  private assertEnvelopeOwner(envelope: AccountEnvelope) {
    if (!envelope || envelope.version !== 1 || envelope.locator.accountId !== this.accountId) {
      throw new Error('envelope accountId does not match owner-scoped DKVS client');
    }
  }
}
