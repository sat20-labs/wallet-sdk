export type RecoveryMode = '2of2' | '2of3';

export type RecoveryShareRole = 'user' | 'dkvs' | 'guardian';

export interface ManagedSubAccount {
  /** Zero-based derivation index within the parent wallet. */
  index: number;
  /** Ordinals DID name assigned to this sub-account. */
  name: string;
}

export interface ManagedWallet {
  /** User-facing wallet name. */
  name: string;
  /** BIP-39 mnemonic for the wallet. */
  mnemonic: string;
  /** Number of derived sub-accounts to restore. */
  accountCount: number;
  /** Names for each derived sub-account. */
  subAccounts: ManagedSubAccount[];
}

export interface AccountBackup {
  version: 1;
  wallets: ManagedWallet[];
}

export interface AccountLocator {
  version: 1;
  accountId: string;
  packageId: string;
  recoveryMode: RecoveryMode;
}

export interface RecoveryShare {
  version: 1;
  packageId: string;
  threshold: 2;
  total: 2 | 3;
  index: number;
  role: RecoveryShareRole;
  /** Canonical public-share string produced by secrets.js-grempe with GF(2^8). */
  data: string;
  /** Hex checksum over all share metadata and data. */
  checksum: string;
}

export interface EncryptedAccountBackup {
  algorithm: 'aes-256-gcm';
  iv: string;
  authTag: string;
  ciphertext: string;
}

export interface AccountEnvelope {
  version: 1;
  locator: AccountLocator;
  encryptedBackup: EncryptedAccountBackup;
}

export interface RecoveryManifest {
  version: 1;
  locator: AccountLocator;
  threshold: 2;
  total: 2 | 3;
  /** SHA-256 hash of the encrypted account envelope. */
  envelopeHash: string;
  createdAt: number;
}

export interface AccountRecoveryPackage {
  envelope: AccountEnvelope;
  manifest: RecoveryManifest;
  userShare: RecoveryShare;
  dkvsShare: RecoveryShare;
  guardianShare?: RecoveryShare;
}

export interface RecoveryQuestion {
  id: string;
  prompt: string;
  /**
   * Optional private context shown only to the user, for example a book edition.
   * It must not be written to public DKVS records in plaintext.
   */
  privateReference?: string;
  normalization?: 'exact' | 'case-insensitive';
}

export interface RecoveryAnswer {
  questionId: string;
  answer: string;
}

export interface RecoveryQuestionSet {
  version: 1;
  questions: RecoveryQuestion[];
  /** Number of answer tokens required by the Fuzzy Vault implementation. */
  requiredAnswers: number;
}

export interface WalletRecoverySummary {
  name: string;
  accountCount: number;
  subAccountNames: string[];
}

export interface AccountRecoverySummary {
  accountId: string;
  packageId: string;
  recoveryMode: RecoveryMode;
  wallets: WalletRecoverySummary[];
}

export interface NewDeviceRecoveryResult {
  backup: AccountBackup;
  summary: AccountRecoverySummary;
  rehearsalCompleted: true;
}

export interface CreateAccountPackageOptions {
  accountId: string;
  backup: AccountBackup;
  recoveryMode: RecoveryMode;
}

export interface NewDeviceRecoveryOptions {
  locator: AccountLocator;
  shares: RecoveryShare[];
  confirm: (summary: AccountRecoverySummary) => boolean | Promise<boolean>;
  /** PWA/native integration persists the recovered backup in platform-secure storage. */
  persist: (backup: AccountBackup) => void | Promise<void>;
}
