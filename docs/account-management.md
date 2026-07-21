# Wallet SDK 自托管账户管理系统需求与设计

版本：v0.3  
状态：开发指导稿  
依赖：SatoshiNet DKVS、Wallet SDK 统一派生模型

## 1. 目标

在 Wallet SDK 中新增自托管账户管理模块，用于：

1. 加密备份多个钱包的助记词；
2. 保存每个钱包需要恢复的子账户数量；
3. 保存钱包名称和子账户名称；
4. 将子账户名称作为 Ordinals DID 处理；
5. 将账户密文保存到用户自己的 DKVS `/personal/<account_id>/...` 空间；
6. 使用 Shamir 2/2 或 2/3 分片恢复账户；
7. 把添加新设备设计成一次完整恢复演练；
8. 保证恢复和解密始终在本地完成。

账户管理只保存恢复账户本身所需的数据。链上 contracts、资产状态、余额和交易历史由 indexer 重新获取；应用设置由具体应用自行管理。

## 2. 自托管边界

账户数据的安全边界如下：

```text
DKVS 只保存密文
单个 Shamir 分片不能恢复账户
Wallet service 不能解密账户
Guardian 单独不能恢复账户
账户解密和 Shamir 合并只在用户设备本地完成
```

账户 DKVS record 使用账户 owner 签名，并由同一个账户对应的费用支付能力承担费用。v1 不支持 record signer 与 fee payer 分离。

## 3. 账户备份数据模型

Wallet SDK 当前采用统一派生模式，因此账户备份只保存以下信息：

```text
AccountBackup
  version
  wallets[]
    wallet name
    mnemonic
    sub-account count
    sub-accounts[]
      derivation index
      Ordinals DID name
```

建议结构：

```ts
interface AccountBackup {
  version: 1;
  wallets: ManagedWallet[];
}

interface ManagedWallet {
  name: string;
  mnemonic: string;
  accountCount: number;
  subAccounts: ManagedSubAccount[];
}

interface ManagedSubAccount {
  index: number;
  name: string; // Ordinals DID
}
```

约束：

1. 至少保存一个钱包；
2. 钱包名称非空且在账户内唯一；
3. `accountCount` 与 `subAccounts.length` 一致；
4. 子账户索引从 `0` 到 `accountCount - 1`，不能重复或缺失；
5. 子账户 DID 名称非空且在对应钱包内唯一；
6. 助记词只存在于本地明文内存和加密账户备份中。

## 4. 账户主秘密与加密

创建账户备份时，本地生成 32 字节随机账户主秘密：

```text
AccountSecret = random(32 bytes)
```

账户主秘密用于派生账户备份加密密钥：

```text
BackupKey = HMAC-SHA256(
  key = AccountSecret,
  data = domain || account_id || package_id
)
```

账户备份使用 AES-256-GCM 加密，并绑定以下 AAD：

```text
version
account_id
package_id
recovery_mode
```

账户密文包括：

```text
algorithm
aes-gcm iv
auth tag
ciphertext
```

Recovery Manifest 保存账户加密信封的 SHA-256 hash，用于确认 manifest 与 DKVS 中的 envelope 属于同一版本。该 hash 只覆盖密文信封，不覆盖明文助记词数据。

`AccountSecret` 在生成恢复分片或恢复完成后应尽快从临时内存清除。

## 5. Shamir 恢复模式

所有恢复分片统一使用 Shamir Secret Sharing。

### 5.1 2/2

```text
S_user + S_dkvs -> AccountSecret
```

保存位置：

- `S_user`：用户保存；
- `S_dkvs`：加密后保存到 DKVS，并由 Fuzzy Vault 解锁。

### 5.2 2/3

```text
S_user
S_dkvs
S_guardian
```

任意两片恢复：

```text
S_user + S_dkvs
S_user + S_guardian
S_dkvs + S_guardian
```

`S_guardian` 加密后保存到好友 mailbox 的专用 share 路径。

### 5.3 分片格式

```text
version
package_id
threshold
share_count
share_index
share_role
share_payload
checksum
```

分片必须校验：

1. package ID 一致；
2. threshold 和 share count 一致；
3. share index 唯一；
4. checksum 正确；
5. 恢复出的账户通过 AES-GCM 认证，并且 manifest 中的 encrypted envelope hash 与账户密文一致。

## 6. 基于私人知识问题的 Fuzzy Vault

Fuzzy Vault 不使用纯随机记忆锚点作为默认产品体验。默认采用用户能够长期记住、答案相对明确、但外部人员难以枚举的私人知识问题。

示例：

```text
你最喜欢的一本书的指定版本，第十页最后十个字是什么？
你长期保存的一张私人纸条中，指定句子的内容是什么？
你与家人约定但从未公开使用的一段长口令是什么？
```

### 6.1 问题选择要求

1. 不能只使用一个问题；
2. 建议设置 3–5 个相互独立的问题；
3. 答案空间应足够大，避免生日、学校、宠物名、出生地等常见安全问题；
4. 问题涉及书籍时，应明确版本、语言和页码，避免不同版本导致答案不一致；
5. 问题和私人 reference 不应以明文写入公开 DKVS；
6. 创建时要求用户连续输入两次答案，确认长期可重复；
7. 设置完成后立即做一次恢复演练。

单个问题的安全性无法可靠量化，因此 Fuzzy Vault 的安全性来自多个独立答案、容错阈值、Shamir 阈值和用户分片的共同作用。

### 6.2 答案规范化

本地规范化规则：

1. Unicode NFKC；
2. 去除首尾空白；
3. 连续空格、Tab 和换行折叠为一个空格；
4. 默认保留标点和大小写；
5. 问题可明确声明大小写不敏感。

每个答案生成独立 token：

```text
token = SHA256(domain || question_id || normalized_answer)
```

Fuzzy Vault 只用于恢复 `S_dkvs` 的随机加密密钥，不直接保存账户主秘密，也不直接保存明文 Shamir 分片。

实际 Fuzzy Vault 多项式、chaff、容错和参数应由独立、经过审查的实现提供；Wallet SDK 账户模块通过 `FuzzyVaultProvider` 接口调用。

## 7. DKVS 数据组织

账户数据放在用户自己的 personal 空间：

```text
/personal/<account_id>/account/envelope
/personal/<account_id>/account/recovery/<package_id>/manifest
/personal/<account_id>/account/recovery/<package_id>/share/dkvs
/personal/<account_id>/account/recovery/<package_id>/questions
```

Guardian 分片保存到好友 mailbox：

```text
/mail/<guardian_mailbox_id>/share/<package_id>/<share_id>
```

Guardian 请求与响应：

```text
/mail/<guardian_mailbox_id>/msg/<sender_id>/<request_id>
/mail/<reply_mailbox_id>/msg/<sender_id>/<response_id>
```

账户 SDK 使用 owner-scoped DKVS client：

```ts
interface OwnerScopedDkvsClient {
  readonly accountId: string;
  put(key: string, value: Buffer): Promise<void>;
  get(key: string): Promise<Buffer | null>;
}
```

该 client 的实现必须使用账户 owner 身份完成 record 签名和费用支付。账户模块不接受单独 payer 参数。

## 8. 添加新设备即恢复演练

新增设备不采用直接复制明文助记词或静默设备迁移。新设备必须走与账户找回相同的恢复流程，使用户真正理解自己的恢复路径。

### 8.1 流程

1. 新设备扫描 Account Locator 或用户分片；
2. 从 DKVS 读取账户密文和 recovery manifest；
3. 用户提供满足阈值的两份 Shamir 分片；
4. 本地恢复 `AccountSecret`；
5. 本地解密账户备份；
6. 页面只展示钱包名称、子账户数量和 DID 名称，不展示助记词；
7. 用户确认恢复内容正确；
8. 将账户备份写入新设备安全存储；
9. 标记本次操作为恢复演练已完成。

### 8.2 产品要求

界面应使用普通语言表达：

```text
第 1 步：找到你的账户
第 2 步：提供两份恢复材料
第 3 步：确认钱包和 DID 名称
第 4 步：在这台设备上启用账户
```

整个过程不要求用户理解助记词导入、派生路径或 Shamir 算法。

## 9. Account Locator

Locator 用于在新设备上找到 DKVS 数据：

```ts
interface AccountLocator {
  version: 1;
  accountId: string;
  packageId: string;
  recoveryMode: '2of2' | '2of3';
}
```

Locator 可以公开，可编码在用户分片和二维码中。Locator 不包含账户主秘密或助记词。

## 10. SDK 模块

### 10.1 AccountManager

```text
createRecoveryPackage
publishRecoveryPackage
recoverAccount
recoverAccountFromDkvs
restoreOnNewDevice
```

### 10.2 Shamir

```text
splitAccountSecret
combineAccountSecret
encodeRecoveryShare
decodeRecoveryShare
```

### 10.3 Recovery Questions

```text
validateRecoveryQuestionSet
normalizeRecoveryAnswer
createRecoveryAnswerTokens
FuzzyVaultProvider
```

### 10.4 DKVS Repository

```text
saveEnvelope
getEnvelope
saveManifest
getManifest
saveDkvsShareCapsule
getDkvsShareCapsule
saveEncryptedQuestionSet
getEncryptedQuestionSet
```

## 11. 创建流程

```text
1. Wallet SDK 收集多个钱包的助记词、钱包名、子账户数量和 DID 名称。
2. 本地验证账户备份结构。
3. 生成 32-byte AccountSecret。
4. 使用 Shamir 生成 2/2 或 2/3 分片。
5. 使用 AccountSecret 加密账户备份。
6. 将 envelope 和 manifest 写入 DKVS。
7. 将 S_dkvs 交给 Fuzzy Vault provider 生成加密 capsule 后写入 DKVS。
8. 2/3 模式下，将 S_guardian 加密后写入 Guardian mailbox share 路径。
9. 用户保存 S_user。
10. 立即执行一次恢复演练。
```

## 12. 恢复流程

```text
1. 解析 Account Locator。
2. 从 DKVS 获取 envelope 和 manifest。
3. 收集任意两份合法 Shamir 分片。
4. 本地组合 AccountSecret。
5. 本地解密 AccountBackup。
6. 校验 AES-GCM 认证，并确认 manifest 的 encrypted envelope hash 与 DKVS envelope 一致。
7. 恢复每个钱包助记词。
8. 按统一派生规则恢复指定数量的子账户。
9. 将备份中的子账户名称恢复为对应 Ordinals DID 名称。
10. 从 indexer 重新获取 contracts、资产、余额和交易状态。
```

## 13. 泄露处理

- 单个分片泄露：重新生成 recovery package 和全部分片；账户助记词可保持不变。
- 任意达到阈值的两片泄露：视为账户主秘密泄露，应重新加密账户备份并评估钱包助记词迁移。
- 账户密文泄露：只要阈值恢复材料未泄露，账户助记词仍受保护。
- 新设备不可信：不得在该设备完成恢复。

## 14. v1 数据范围

账户管理 v1 保存：

1. 多个钱包助记词；
2. 钱包名称；
3. 每个钱包的子账户数量；
4. 每个子账户的派生索引；
5. 每个子账户的 Ordinals DID 名称；
6. recovery manifest 和加密恢复材料。

链上 contracts、余额、资产、交易历史和应用设置由 indexer 或应用重新获取。

## 15. 第一阶段实现范围

第一阶段 PR 实现：

1. 聚焦账户的数据模型和校验；
2. Shamir 2/2 与 2/3；
3. 分片编码、checksum 和 package 防混用；
4. AES-256-GCM 账户备份加密；
5. owner-scoped DKVS repository 接口和 key 构造；
6. 私人知识问题规范化与 token 生成；
7. Fuzzy Vault provider 接口；
8. 新设备恢复演练 API；
9. 单元测试。

后续在独立 PR 中接入真实 DKVS HTTP / record 签名实现和经过审查的 Fuzzy Vault 算法实现。
