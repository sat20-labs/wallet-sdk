import { AccountBackup, ManagedSubAccount, ManagedWallet } from './types';

export class AccountValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AccountValidationError';
  }
}

function assertNonEmptyString(value: string, field: string) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new AccountValidationError(`${field} must be a non-empty string`);
  }
}

function normalizeSubAccount(account: ManagedSubAccount, walletName: string): ManagedSubAccount {
  if (!Number.isInteger(account.index) || account.index < 0) {
    throw new AccountValidationError(`wallet ${walletName} contains an invalid sub-account index`);
  }
  assertNonEmptyString(account.name, `wallet ${walletName} sub-account name`);
  return {
    index: account.index,
    name: account.name.trim()
  };
}

function normalizeWallet(wallet: ManagedWallet): ManagedWallet {
  assertNonEmptyString(wallet.name, 'wallet name');
  assertNonEmptyString(wallet.mnemonic, `wallet ${wallet.name} mnemonic`);

  if (!Number.isInteger(wallet.accountCount) || wallet.accountCount < 0) {
    throw new AccountValidationError(`wallet ${wallet.name} accountCount must be a non-negative integer`);
  }
  if (!Array.isArray(wallet.subAccounts)) {
    throw new AccountValidationError(`wallet ${wallet.name} subAccounts must be an array`);
  }
  if (wallet.subAccounts.length !== wallet.accountCount) {
    throw new AccountValidationError(
      `wallet ${wallet.name} accountCount does not match the number of named sub-accounts`
    );
  }

  const subAccounts = wallet.subAccounts.map((item) => normalizeSubAccount(item, wallet.name));
  const indexes = new Set<number>();
  const names = new Set<string>();
  for (const account of subAccounts) {
    if (account.index >= wallet.accountCount) {
      throw new AccountValidationError(`wallet ${wallet.name} contains a sub-account index outside accountCount`);
    }
    if (indexes.has(account.index)) {
      throw new AccountValidationError(`wallet ${wallet.name} contains a duplicate sub-account index`);
    }
    if (names.has(account.name)) {
      throw new AccountValidationError(`wallet ${wallet.name} contains a duplicate sub-account name`);
    }
    indexes.add(account.index);
    names.add(account.name);
  }

  for (let index = 0; index < wallet.accountCount; index++) {
    if (!indexes.has(index)) {
      throw new AccountValidationError(`wallet ${wallet.name} is missing sub-account index ${index}`);
    }
  }

  return {
    name: wallet.name.trim(),
    mnemonic: wallet.mnemonic.trim().replace(/\s+/g, ' '),
    accountCount: wallet.accountCount,
    subAccounts: subAccounts.sort((a, b) => a.index - b.index)
  };
}

export function normalizeAccountBackup(backup: AccountBackup): AccountBackup {
  if (!backup || backup.version !== 1 || !Array.isArray(backup.wallets)) {
    throw new AccountValidationError('invalid account backup');
  }
  if (backup.wallets.length === 0) {
    throw new AccountValidationError('an account backup must contain at least one wallet');
  }

  const wallets = backup.wallets.map(normalizeWallet);
  const walletNames = new Set<string>();
  for (const wallet of wallets) {
    if (walletNames.has(wallet.name)) {
      throw new AccountValidationError(`duplicate wallet name: ${wallet.name}`);
    }
    walletNames.add(wallet.name);
  }

  return {
    version: 1,
    wallets
  };
}
