# Wallet SDK 自托管账户管理系统需求与设计

版本：v0.4  
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
8. 保证恢复和解密始终在用户本地完成；
9. 通过 DKVS AUTOPAY 完成账户数据写入和长期保存；
10. 在 PWA / 原生钱包层使用平台安全能力保护本地账户。

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

账户 DKVS record 使用账户 owner 签名，并由同一个账户对应的 AUTOPAY 能力承担费用。账户模块不接受独立 payer 参数。

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

TypeScript 结构：

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

账户管理不保存：

```text
contracts
余额
资产状态
交易历史
应用设置
```

这些数据由 indexer 或应用重新获取。

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

Wallet SDK 使用 `secrets.js-grempe@2.0.0` 作为工程实现。该实现同时支持 Node.js 和浏览器，公开 share 使用其标准格式；账户模块只在外层增加 package ID、角色和 checksum。该实现曾被纳入 Cure53 的 PrivEOS 安全审计范围，审计报告确认其 Shamir 实现符合规格。

### 5.1 普通用户默认模式：2/3 便利恢复

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

这一模式适合普通用户。即使用户没有长期保管好 `S_user`，仍可通过 DKVS 知识恢复和 Guardian 找回账户。

保存位置：

- `S_user`：可选由用户保存，用于独立增强安全和恢复韧性；
- `S_dkvs`：加密后保存到 DKVS，由 Fuzzy Vault 解锁；
- `S_guardian`：加密后保存到好友 mailbox 的专用 share 路径。

### 5.2 增强安全模式：2/2 用户分片必需

```text
S_user + S_dkvs -> AccountSecret
```

这一模式适合愿意自行保管恢复材料的用户。`S_user` 是密码学上的必需分片，没有用户自己保存的分片就不能恢复账户。

保存位置：

- `S_user`：由用户保存；
- `S_dkvs`：加密后保存到 DKVS，并由 Fuzzy Vault 解锁。

该模式牺牲部分便利性，换取更强的“用户必须参与”约束。

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

`share_payload` 是 `secrets.js-grempe` 产生的 canonical public share string。

分片必须校验：

1. package ID 一致；
2. threshold 和 share count 一致；
3. share index 唯一；
4. share role 与 index 一致；
5. checksum 正确；
6. share 的 GF 位数和公开 share id 与外层 metadata 一致；
7. 恢复出的账户通过 AES-GCM 认证；
8. manifest 中的 encrypted envelope hash 与 DKVS envelope 一致。

## 6. 基于私人知识问题的 Fuzzy Vault

Fuzzy Vault 默认采用用户能够长期记住、答案相对明确、但外部人员难以枚举的私人知识问题，而不是纯随机记忆锚点。

示例：

```text
你最喜欢的一本书的指定版本，第十页最后十个字是什么？
你长期保存的一张私人纸条中，指定句子的内容是什么？
你与家人约定但从未公开使用的一段长口令是什么？
```

### 6.1 问题选择要求

1. 使用 3–5 个相互独立的问题；
2. Fuzzy Vault 设置至少需要其中两个或更多答案；
3. 答案空间应足够大；
4. 不使用生日、学校、宠物名、出生地等常见安全问题；
5. 涉及书籍时明确版本、语言和页码；
6. 问题的私人 reference 不以明文写入公开 DKVS；
7. 创建时要求用户连续输入两次答案；
8. 设置完成后立即做恢复演练；
9. 定期在本地提示用户验证仍能回答。

单个问题的安全性无法可靠量化。整体安全性来自多个独立答案、Fuzzy Vault 容错阈值、Shamir 阈值和 Guardian / 用户分片的共同作用。

### 6.2 答案规范化

本地规范化规则：

1. Unicode NFKC；
2. 去除首尾空白；
3. 连续空格、Tab 和换行折叠为一个空格；
4. 默认保留标点和大小写；
5. 问题可明确声明大小写不敏感。

每个答案生成独立 token：

```text
token = SHA256(
  domain ||
  package_specific_context ||
  question_id ||
  normalized_answer
)
```

`package_specific_context` 使用当前 recovery package ID 或独立随机 salt，避免不同账户或不同恢复包复用同一答案时产生可关联 token。

Fuzzy Vault 只用于恢复 `S_dkvs` 的随机加密密钥，不直接保存 AccountSecret，也不直接保存明文 Shamir 分片。

### 6.3 实现边界

账户模块通过以下接口调用 Fuzzy Vault：

```ts
interface FuzzyVaultProvider {
  lock(secret: Buffer, tokens: Buffer[], requiredTokens: number): Promise<Buffer>;
  unlock(vault: Buffer, tokens: Buffer[]): Promise<Buffer>;
}
```

具体多项式、chaff、集合匹配和容错实现必须经过单独代码审查和测试。历史 TinyVerse Go 实现计划作为参考移植；在源文件可访问并完成审查前，不将未经核实的副本加入 Wallet SDK。

## 7. DKVS 数据组织与 AUTOPAY

账户数据放在用户自己的 personal 空间：

```text
/personal/<account_id>/account/recovery/<package_id>/envelope
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

真实 DKVS adapter 使用账户 owner 钱包：

1. 构造 `/personal/<account_id>/...` record；
2. 附加 AUTOPAY fee proof；
3. 使用同一 owner key 签名；
4. 发布到 DKVS；
5. 验证 bootstrap、core、miner 均可读取；
6. 验证 prefix list 和 usage 统计。

写入顺序：

```text
envelope
share/dkvs
questions
manifest
```

Manifest 最后写入，作为应用级 commit marker。读取到 manifest 后，客户端仍要校验 envelope hash 和全部密码学认证。

## 8. 添加新设备即恢复演练

新增设备不直接复制明文助记词，也不静默迁移本地数据库。新设备走与账户找回相同的完整恢复流程。

### 8.1 流程

1. 新设备扫描 Account Locator 或用户分片；
2. 从 DKVS 读取账户密文和 recovery manifest；
3. 选择恢复方式：知识问题、Guardian 或用户分片；
4. 收集满足阈值的两份 Shamir 分片；
5. 本地恢复 `AccountSecret`；
6. 本地解密账户备份；
7. 页面只展示钱包名称、子账户数量和 DID 名称，不展示助记词；
8. 用户确认恢复内容正确；
9. 在新设备安全存储中启用账户；
10. 标记本次操作为恢复演练已完成。

### 8.2 产品表达

```text
第 1 步：找到你的账户
第 2 步：选择找回方式
第 3 步：完成两个恢复证明
第 4 步：确认钱包和 DID 名称
第 5 步：在这台设备上启用账户
```

用户不需要理解助记词导入、派生路径、Shamir 或 Fuzzy Vault。

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

## 10. PWA / 原生钱包安全设备存储

Wallet SDK 只通过 `persist` 回调把恢复后的账户交给钱包层。平台安全存储由 sat20wallet PWA / Capacitor 应用负责。

### 10.1 本地存储对象

本地设备不把助记词、AccountSecret 或可直接解锁账户的密码哈希明文写入 localStorage / IndexedDB。

推荐模型：

```text
DeviceWrappingKey = random(32 bytes)
WrappedAccountSecret = AEAD(DeviceWrappingKey, AccountSecret)
EncryptedAccountEnvelope = DKVS envelope or local encrypted cache
```

IndexedDB 只保存：

```text
account_id
package_id
encrypted account envelope
wrapped AccountSecret
device key slot metadata
```

`DeviceWrappingKey` 由平台安全能力保护。

### 10.2 Android / iOS 原生应用

sat20wallet 原生移动端基于 Capacitor。

实现一个统一的 Capacitor `SecureAccountStorage` 插件：

- Android：使用 hardware-backed Android Keystore 生成 AES-GCM key，设置 `BiometricPrompt` / device credential 访问控制；
- iOS：使用 Keychain，并设置 `SecAccessControl` 的 user presence / biometry current set；
- 插件只暴露 `seal`、`unseal`、`delete`、`capabilities`；
- JavaScript 不持久保存原生 key；
- 生物识别是硬件 key 的访问控制，而不是“验证成功后从 localStorage 读取密码”。

### 10.3 macOS / Windows / 纯 PWA

浏览器 PWA 无法直接统一调用 macOS Keychain 或 Windows DPAPI，因此采用分级策略：

1. 首选 WebAuthn PRF / passkey 派生设备包装密钥；
2. PRF 不可用时，使用本地设备 PIN / 长密码通过 Argon2id 派生 KEK；
3. KEK 只解密随机 `DeviceWrappingKey`；
4. 忘记设备 PIN 时执行完整账户恢复，不提供服务器重置；
5. 所有密文和盐保存在 IndexedDB；
6. 解锁后设置短会话超时，并在锁定时清理内存中的 AccountSecret 和助记词。

### 10.4 统一接口

```ts
interface SecureAccountStorage {
  capabilities(): Promise<SecureStorageCapabilities>;
  seal(accountId: string, accountSecret: Uint8Array): Promise<DeviceKeySlot>;
  unseal(accountId: string, requireUserPresence?: boolean): Promise<Uint8Array>;
  remove(accountId: string): Promise<void>;
}
```

平台实现：

```text
CapacitorNativeSecureStorage   Android / iOS
WebAuthnPrfSecureStorage       macOS / Windows / supported mobile browsers
PinWrappedSecureStorage        browser fallback
```

### 10.5 现有实现迁移要求

现有 PWA IndexedDB adapter 可以继续保存非秘密 UI 状态和密文，但账户秘密必须使用上述 secure storage 层。

现有生物识别代码中以下模式不用于账户秘密：

```text
Math.random challenge
base64 存储 hashed password
生物识别成功后直接信任 localStorage 中的密码
```

## 11. 浏览器构建与运行验证

账户模块目前使用 Node-compatible `crypto` API。Node 单元测试通过并不自动证明浏览器 PWA 可运行，因为浏览器没有原生 Node `crypto`、`Buffer`、`process` 等对象。

因此需要两个独立测试层：

1. Node / TypeScript 单元测试：验证数据模型、Shamir、AES-GCM 和恢复逻辑；
2. Browser bundle / PWA smoke test：验证 Vite / Webpack 的 polyfill 或 Web Crypto adapter 能在真实浏览器加载并完成创建、加密和恢复。

CI 必须至少执行 CommonJS build、browser ESM build 和账户测试。PWA 接入时再增加真实浏览器 smoke test。

## 12. SDK 模块

### 12.1 AccountManager

```text
createRecoveryPackage
publishRecoveryPackage
recoverAccount
recoverAccountFromDkvs
restoreOnNewDevice
```

### 12.2 Shamir

```text
splitAccountSecret
combineAccountSecret
encodeRecoveryShare
decodeRecoveryShare
```

### 12.3 Recovery Questions

```text
validateRecoveryQuestionSet
confirmRecoveryAnswers
normalizeRecoveryAnswer
createRecoveryAnswerTokens
FuzzyVaultProvider
```

### 12.4 DKVS Repository

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

## 13. 创建流程

```text
1. Wallet SDK 收集多个钱包的助记词、钱包名、子账户数量和 DID 名称。
2. 本地验证账户备份结构。
3. 生成 32-byte AccountSecret。
4. 使用工程化 Shamir 实现生成 2/2 或 2/3 分片。
5. 使用 AccountSecret 加密账户备份。
6. 将 S_dkvs 交给 Fuzzy Vault provider 生成 capsule。
7. 2/3 模式下，将 S_guardian 加密后写入 Guardian mailbox share 路径。
8. 使用 owner wallet 和 AUTOPAY 依次发布 envelope、share、questions、manifest。
9. 根据模式提示用户保存或跳过 S_user。
10. 立即执行一次恢复演练。
```

## 14. 恢复流程

```text
1. 解析 Account Locator。
2. 从 DKVS 获取 envelope 和 manifest。
3. 选择知识问题、Guardian 或用户分片恢复来源。
4. 收集任意两份合法 Shamir 分片。
5. 本地组合 AccountSecret。
6. 本地解密 AccountBackup。
7. 校验 AES-GCM 认证和 manifest envelope hash。
8. 恢复每个钱包助记词。
9. 按统一派生规则恢复指定数量的子账户。
10. 恢复子账户 Ordinals DID 名称。
11. 从 indexer 重新获取 contracts、资产、余额和交易状态。
12. 由 PWA / 原生钱包安全存储保护本地账户。
```

## 15. 泄露处理

- 单个分片泄露：重新生成 recovery package 和全部分片；账户助记词可保持不变。
- 任意达到阈值的两片泄露：视为 AccountSecret 泄露，应重新加密账户备份并评估钱包助记词迁移。
- 账户密文泄露：只要阈值恢复材料未泄露，账户助记词仍受保护。
- 新设备不可信：不得在该设备完成恢复。
- Guardian 或知识问题疑似泄露：立即轮换 recovery package。

## 16. 测试要求

### 16.1 Wallet SDK

1. Shamir 2/2；
2. Shamir 2/3 三种合法组合；
3. `secrets.js-grempe` share 互操作；
4. 1,000 组随机 2/3 恢复；
5. package ID 防混用；
6. metadata / checksum 篡改检测；
7. AES-256-GCM 加解密和认证失败；
8. focused backup 数据校验；
9. 新设备完整恢复演练；
10. 私人知识答案规范化、二次确认和 package-specific token。

### 16.2 DKVS AUTOPAY E2E

使用真实 SatoshiNet 三节点 e2e fixture：

1. 部署并激活 AUTOPAY；
2. 使用 account owner 写入 `/personal/<account_id>/account/recovery/<package_id>/...`；
3. envelope、share、questions、manifest 全部携带 AUTOPAY fee proof；
4. bootstrap、core、miner 都能读取；
5. prefix subscription 能同步完整恢复包；
6. prefix list 返回完整 record 数；
7. usage 统计包含全部账户恢复数据；
8. manifest 最后写入。

### 16.3 PWA / 设备存储

1. Android Keystore seal / unseal；
2. iOS Keychain seal / unseal；
3. WebAuthn PRF key slot；
4. PIN + Argon2id fallback；
5. IndexedDB 中无明文 AccountSecret / 助记词；
6. 生物识别取消后不能解锁；
7. 清除浏览器数据后可通过账户恢复重新添加设备；
8. 会话锁定后内存 secret 被清理。

## 17. 第一阶段实现范围

第一阶段实现：

1. 聚焦账户的数据模型和校验；
2. 工程化 Shamir 2/2 与 2/3；
3. 分片编码、checksum 和 package 防混用；
4. AES-256-GCM 账户备份加密；
5. owner-scoped DKVS repository 接口和 key 构造；
6. 私人知识问题规范化、二次确认与 token 生成；
7. Fuzzy Vault provider 接口；
8. 新设备恢复演练 API；
9. Wallet SDK 单元测试；
10. DKVS AUTOPAY 三节点 e2e；
11. 跨平台安全设备存储设计。

具体 TinyVerse Fuzzy Vault 移植和 PWA / Capacitor secure storage 实现，在对应源代码完成审查后继续落地。
