declare function describe(name: string, fn: () => void): void;
declare function it(name: string, fn: () => void | Promise<void>): void;

import { strict as assert } from 'assert';
import { randomBytes } from 'crypto';
import * as secrets from 'secrets.js-grempe';
import {
  AccountBackup,
  AccountManager,
  DkvsAccountRepository,
  OwnerScopedDkvsClient,
  RecoveryShare,
  accountIdFromPublicKey,
  combineAccountSecret,
  confirmRecoveryAnswers,
  createRecoveryAnswerTokens,
  decodeRecoveryShare,
  encodeRecoveryShare,
  normalizeRecoveryAnswer,
  splitAccountSecret,
  validateRecoveryQuestionSet
} from '../../src/account';

class MemoryDkvsClient implements OwnerScopedDkvsClient {
  readonly accountId: string;
  readonly values = new Map<string, Buffer>();

  constructor(accountId: string) {
    this.accountId = accountId;
  }

  async put(key: string, value: Buffer): Promise<void> {
    this.values.set(key, Buffer.from(value));
  }

  async get(key: string): Promise<Buffer | null> {
    const value = this.values.get(key);
    return value ? Buffer.from(value) : null;
  }
}

const backup: AccountBackup = {
  version: 1,
  wallets: [
    {
      name: '主钱包',
      mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      accountCount: 2,
      subAccounts: [
        { index: 0, name: 'alice.sats' },
        { index: 1, name: 'savings.sats' }
      ]
    },
    {
      name: '工作钱包',
      mnemonic: 'legal winner thank year wave sausage worth useful legal winner thank yellow',
      accountCount: 1,
      subAccounts: [{ index: 0, name: 'studio.sats' }]
    }
  ]
};

const questionSet = {
  version: 1 as const,
  requiredAnswers: 2,
  questions: [
    { id: 'book-page', prompt: '最喜欢的一本书第十页最后十个字是什么？' },
    { id: 'private-note', prompt: '你保存的一张私人纸条上的指定句子是什么？' },
    { id: 'family-code', prompt: '你和家人约定的长口令是什么？', normalization: 'case-insensitive' as const }
  ]
};

const answers = [
  { questionId: 'book-page', answer: '  月光落在旧桥尽头  ' },
  { questionId: 'private-note', answer: '风从南边的窗户进来' },
  { questionId: 'family-code', answer: 'Silver-River-1987' }
];

describe('account management', () => {
  it('restores a 2-of-2 account package', () => {
    const manager = new AccountManager();
    const recoveryPackage = manager.createRecoveryPackage({
      accountId: 'a'.repeat(64),
      backup,
      recoveryMode: '2of2'
    });

    const restored = manager.recoverAccount(recoveryPackage.envelope, [
      recoveryPackage.userShare,
      recoveryPackage.dkvsShare
    ]);
    assert.deepEqual(restored, backup);
  });

  it('restores all 2-of-3 share combinations', () => {
    const manager = new AccountManager();
    const recoveryPackage = manager.createRecoveryPackage({
      accountId: 'b'.repeat(64),
      backup,
      recoveryMode: '2of3'
    });

    const combinations = [
      [recoveryPackage.userShare, recoveryPackage.dkvsShare],
      [recoveryPackage.userShare, recoveryPackage.guardianShare],
      [recoveryPackage.dkvsShare, recoveryPackage.guardianShare]
    ];

    for (const shares of combinations) {
      assert.deepEqual(manager.recoverAccount(recoveryPackage.envelope, shares), backup);
    }
  });

  it('uses canonical shares that interoperate with secrets.js-grempe', () => {
    const secret = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
    const shares = splitAccountSecret(secret, '01'.repeat(16), '2of3');

    for (const share of shares) {
      const components = secrets.extractShareComponents(share.data);
      assert.equal(components.bits, 8);
      assert.equal(components.id, share.index);
    }

    const restoredByProvider = Buffer.from(secrets.combine([shares[0].data, shares[2].data]), 'hex');
    assert.equal(restoredByProvider.equals(secret), true);
    assert.equal(combineAccountSecret([shares[1], shares[2]]).equals(secret), true);
  });

  it('passes 1,000 randomized 2-of-3 recovery checks', () => {
    for (let iteration = 0; iteration < 1000; iteration++) {
      const secret = randomBytes(32);
      const shares = splitAccountSecret(secret, iteration.toString(16).padStart(32, '0'), '2of3');
      assert.equal(combineAccountSecret([shares[0], shares[1]]).equals(secret), true);
      assert.equal(combineAccountSecret([shares[0], shares[2]]).equals(secret), true);
      assert.equal(combineAccountSecret([shares[1], shares[2]]).equals(secret), true);
    }
  });

  it('rejects recovery with one share', () => {
    const manager = new AccountManager();
    const recoveryPackage = manager.createRecoveryPackage({
      accountId: 'c'.repeat(64),
      backup,
      recoveryMode: '2of3'
    });

    assert.throws(() => manager.recoverAccount(recoveryPackage.envelope, [recoveryPackage.userShare]));
  });

  it('rejects modified share metadata and cross-package shares', () => {
    const secret = randomBytes(32);
    const first = splitAccountSecret(secret, '10'.repeat(16), '2of3');
    const second = splitAccountSecret(secret, '20'.repeat(16), '2of3');

    const modified: RecoveryShare = {
      ...first[0],
      packageId: '30'.repeat(16)
    };
    assert.throws(() => combineAccountSecret([modified, first[1]]), /checksum/);
    assert.throws(() => combineAccountSecret([first[0], second[1]]), /different packages/);
  });

  it('encodes and decodes user shares with integrity checks', () => {
    const manager = new AccountManager();
    const recoveryPackage = manager.createRecoveryPackage({
      accountId: 'd'.repeat(64),
      backup,
      recoveryMode: '2of2'
    });
    const encoded = encodeRecoveryShare(recoveryPackage.userShare);
    assert.deepEqual(decodeRecoveryShare(encoded), recoveryPackage.userShare);
    assert.throws(() => decodeRecoveryShare(encoded.slice(0, -1) + 'x'));
  });

  it('publishes and restores through an owner-scoped DKVS repository', async () => {
    const accountId = 'e'.repeat(64);
    const repository = new DkvsAccountRepository(new MemoryDkvsClient(accountId));
    const manager = new AccountManager(repository);
    const recoveryPackage = manager.createRecoveryPackage({ accountId, backup, recoveryMode: '2of2' });
    await manager.publishRecoveryPackage(recoveryPackage);

    const restored = await manager.recoverAccountFromDkvs(recoveryPackage.envelope.locator, [
      recoveryPackage.userShare,
      recoveryPackage.dkvsShare
    ]);
    assert.deepEqual(restored, backup);
  });

  it('uses new-device onboarding as a full recovery rehearsal', async () => {
    const accountId = 'f'.repeat(64);
    const repository = new DkvsAccountRepository(new MemoryDkvsClient(accountId));
    const manager = new AccountManager(repository);
    const recoveryPackage = manager.createRecoveryPackage({ accountId, backup, recoveryMode: '2of3' });
    await manager.publishRecoveryPackage(recoveryPackage);

    let persisted: AccountBackup = null;
    let confirmationSawMnemonic = false;
    const result = await manager.restoreOnNewDevice({
      locator: recoveryPackage.envelope.locator,
      shares: [recoveryPackage.userShare, recoveryPackage.guardianShare],
      confirm: (summary) => {
        confirmationSawMnemonic = JSON.stringify(summary).includes('abandon abandon');
        assert.deepEqual(summary.wallets[0].subAccountNames, ['alice.sats', 'savings.sats']);
        return true;
      },
      persist: (value) => {
        persisted = value;
      }
    });

    assert.equal(result.rehearsalCompleted, true);
    assert.equal(confirmationSawMnemonic, false);
    assert.deepEqual(persisted, backup);
  });

  it('validates focused wallet and sub-account backup data', () => {
    const manager = new AccountManager();
    const invalid: AccountBackup = {
      version: 1,
      wallets: [
        {
          name: 'broken',
          mnemonic: 'one two three',
          accountCount: 2,
          subAccounts: [{ index: 0, name: 'only-one.sats' }]
        }
      ]
    };
    assert.throws(() =>
      manager.createRecoveryPackage({ accountId: '1'.repeat(64), backup: invalid, recoveryMode: '2of2' })
    );
  });

  it('derives the DKVS account id from the owner public key', () => {
    assert.equal(accountIdFromPublicKey(Buffer.from('owner-public-key')).length, 64);
    assert.equal(
      accountIdFromPublicKey(Buffer.from('owner-public-key')),
      accountIdFromPublicKey(Buffer.from('owner-public-key'))
    );
  });

  it('normalizes, confirms and tokenizes private recovery questions locally', () => {
    validateRecoveryQuestionSet(questionSet, answers);
    confirmRecoveryAnswers(questionSet, answers, answers.map((item) => ({ ...item })));
    assert.throws(() =>
      confirmRecoveryAnswers(questionSet, answers, [
        ...answers.slice(0, 2),
        { questionId: 'family-code', answer: 'different-private-answer' }
      ])
    );
    assert.equal(normalizeRecoveryAnswer('  Ｓilver-River-1987  ', 'case-insensitive'), 'silver-river-1987');
    const tokens = createRecoveryAnswerTokens(questionSet, answers, 'package-context-001');
    assert.equal(tokens.length, 3);
    assert.equal(tokens[0].length, 32);
    assert.notDeepEqual(tokens, createRecoveryAnswerTokens(questionSet, answers, 'package-context-002'));
    assert.throws(() => createRecoveryAnswerTokens(questionSet, answers, ''));
  });
});
