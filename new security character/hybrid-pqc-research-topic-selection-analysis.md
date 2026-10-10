# Hybrid PQC 可发表研究问题选题分析

> 评估截止日：2026-09-10。本文以既有 [Hybrid PQC Security Research Map](./hybrid-pqc-security-research-map.md) 为证据底座，只分析尚未闭合的研究问题，不再复述论文内容。2026 年仅 `accepted` 而未正式出版的工作单独标明。

## 结论先行

最值得投入的不是“再验证一个 hybrid handshake 的 secrecy”，而是补齐下列断裂：

```text
primitive binding
      ↓  目前缺少统一提升定理
protocol identity / agreement
      ↓  目前常排除 negotiation、resumption、state recovery
migration state machine
      ↓  目前没有跨 API、跨模式、跨实现的闭环
executable implementation
```

推荐优先级如下：

1. **Hybrid TLS/SSH 的完整 migration transcript 与 downgrade 定理**
2. **从 KEM binding 到 protocol identity / contribution agreement 的提升框架**
3. **Crypto-agile API 下的 cross-mode、cross-protocol hybrid security**
4. **Hybrid ratchet 的 classical/PQC compromise lattice 与 recovery semantics**
5. **Compiler-aware leakage contract 到协议级 graceful degradation 的组合证明**

这五项分别对应 C、A、D、B、E。它们都有明确的攻击者、可构造的最小反例、可复用的形式模型和现实协议对象；同时又避开了已经较拥挤的“generic KEM combiner IND-CCA”与“固定算法套件 secrecy proof”。

---

## 1. 评分标准

| 分数 | Novelty | PQC relevance | Formal verification feasibility | Publication potential |
|---|---|---|---|---|
| 1 | 已有直接完整结果，只能复现 | PQC 只是可替换实例 | 目标性质或实现不可合理形式化 | 主要是工程报告 |
| 2 | 仅增加参数/协议实例 | 与 PQC 有关但非特有 | 需要大量新基础，短期风险高 | workshop/短文更合适 |
| 3 | 已有框架，存在实质扩展 | PQC migration 明显放大问题 | 可完成核心模型，但闭环困难 | 有稳定专业会议潜力 |
| 4 | 只有局部结果，缺统一闭环 | hybrid/PQC 是问题核心 | 现有工具可完成主要部分 | 做出反例与修复可冲安全/形式化强会 |
| 5 | 尚无直接定义或跨层结果 | 没有 PQC/hybrid 就不会以此形式出现 | 可以清晰建模、证明并复现 | 有真实攻击/标准影响时具顶会潜力 |

评分不是论文录用概率。`Publication potential` 假设最终交付至少包含：明确安全定义、机器可检查模型、非平凡反例或定理、真实协议实例，以及可公开 artifact。

工具评分以当前能力而非传统刻板印象为准：Squirrel 已有 computational post-quantum protocol logic，且 2026 年仍在加强其 PQ logical foundations；因此它在 binding、indistinguishability 与关键 ratchet transition 上的评分高于纯 symbolic tool，但在大型 operational state exploration 上仍不如 Tamarin/ProVerif。[18][19]

---

## 2. 总体排名

| 排名 | 候选问题 | 对应重点 | Novelty | PQC relevance | Formal feasibility | Publication potential | 主要风险 |
|---:|---|---|---:|---:|---:|---:|---|
| 1 | 完整 migration transcript：negotiation、fallback、resumption、retry | C | 5 | 5 | 4 | 5 | TLS/SSH 状态空间大；必须固定一个协议版本 |
| 2 | KEM binding → identity/contribution agreement 提升定理 | A | 4 | 5 | 4 | 5 | primitive binding 领域在 2025–2026 快速推进，题目必须落到协议层 |
| 3 | Crypto-agile API 的 cross-mode oracle security | D | 4 | 5 | 4 | 5 | 需要获得真实 API/调用图，否则易退化为纯游戏变体 |
| 4 | Hybrid ratchet compromise lattice 与恢复边界 | B | 4 | 5 | 5 | 5 | secure messaging 研究活跃，需加入未覆盖的 state/session 语义 |
| 5 | Leakage contract → graceful degradation 的跨层组合 | E | 5 | 5 | 2 | 5 | 工具链集成和 binary evidence 难度最高 |
| 6 | Malicious key registration 下的目录/证书 identity binding | A、D | 4 | 5 | 4 | 4 | 若只做 PQXDH 变体会显得增量 |
| 7 | Decapsulation failure 与协议 state consistency | E | 4 | 5 | 3 | 4 | 需证明真实 failure channel 可达，而非只增加抽象 `Leak` |
| 8 | Hybrid PCS 的 session-to-conversation lifting | B、E | 3 | 5 | 4 | 4 | 已有 session-handling 与 2026 SPQR 工作，必须加入设备克隆/回滚或双 ratchet 交互 |

### 不建议作为独立主选题

- **仅证明某个 `KDF(ss_c || ss_pq)` 是 IND-CCA**：generic/composite KEM 已有大量工作，除非加入 binding、cross-mode oracle 或 QROM 新结果。
- **仅把 ML-KEM 抽象成不可破函数后验证 secrecy**：技术门槛与新颖性不足，不能说明 computational PQ soundness。
- **只复现 PQXDH public-key confusion**：问题已被发现和修复；新的贡献必须是统一定义、自动检测或跨协议实例。
- **只把 side-channel 结果建模成 `Reveal(sk_pq)`**：这只能做后果分析，不能建立 implementation-to-protocol 的可信连接。

---

## 3. A：KEM contribution binding 与 identity binding

### A1. 从 primitive KEM binding 到 protocol agreement 的提升定理

**精确未决问题**

给定一个或多个满足指定 `HON/MAL/LEAK-BIND` 或 `SH-CR` 性质的 KEM，以及一个 hybrid combiner，什么是使下列蕴含成立的最小、可组合条件？

```text
component KEM binding
∧ combiner context binding
∧ credential / role binding
⇒ injective agreement(peer, role, suite, pk-set, ct-set, contribution-set, session-key)
```

这里的目标不是再次定义“两个 KEM 输出是否相同”，而是证明一个 protocol participant 接受的 PQ contribution 必然来自其认定身份、角色、suite 和会话中的唯一 key/ciphertext tuple。

**为什么现有工作没有解决**

- PQXDH 工作针对一个具体 protocol 提出额外 binding 性质并证明特定实例，但没有给出可复用的 KEM-to-AKE 提升定理。[2]
- `Keeping Up with the KEMs`、implicitly-rejecting KEM binding 和 2026 combined-KEM binding 已系统推进 primitive/combiner binding，因此“再研究 generic binding”已不够新；它们没有覆盖协议的 credential、role、negotiation、key-id 和 session state。[3][4][5]
- hybrid KEM 的 IND-CCA、extended hybrid security 处理密钥不可区分性和 oracle 接口，不自动推出 peer identity agreement。[6]

**攻击模型**

- **Attacker capability**：`A + K-repl + C-PQ(partial) + MU`；可控制目录或注册一个恶意/重复公钥，可腐化一个 component secret key，可并发启动多个会话。
- **Violated property**：`KEM contribution binding`、`identity binding`、`UKS resistance`、`injective agreement`、`session-key independence`。
- **Minimal attack trace**：

  1. `B` 注册 classical key `pk_c^B` 与 PQ key `pk_pq^B`；攻击者另注册或替换 `pk_pq^M`。
  2. `A` 对所见 tuple encapsulate，并计算 `K = KDF(ss_c, ss_pq, context)`。
  3. 攻击者保持可导出同一 `ss_pq` 的关系，替换 `pk_pq`、`ct_pq`、`key-id` 或 credential owner。
  4. `B` 接受 `K`，但 `A` 与 `B` 对 `(peer, pk_pq, owner, suite)` 的认知不同，或两个逻辑会话共享同一 contribution。

- **Required formal model**：两层模型。上层使用事件 `EncapContribution(owner,role,suite,pk,ct,ss,sid)` 与参数化 agreement；下层给出 KEM binding game，明确 honest、malicious-key 与 leaked-key 三种能力。需要一个 abstraction theorem 说明下层 binding game 足以实现上层不可伪造 constructor，而不是直接把 binding 当无条件等式。

**工具适配性**

| 工具 | 适配度 | 最适合承担的部分 | 主要限制 |
|---|---:|---|---|
| Tamarin | 5/5 | 并发会话、恶意注册、腐化时序、injective agreement、UKS trace | 无法直接证明概率型 KEM binding game |
| ProVerif | 5/5 | 自动搜索 misbinding、key replacement、cross-session correspondence | 复杂 mutable registry 与精细时间顺序不如 Tamarin 自然 |
| Squirrel | 4/5 | 将 symbolic event 与 computational indistinguishability/binding 假设联系 | 新 binding axiom/lemma 需要较多交互证明工作 |
| CryptoVerif/EasyCrypt | 5/5 | KEM binding、hybrid combiner、AKE reduction 与 oracle game | 大型目录和状态机自动化较弱 |

**评分**：Novelty **4/5**；PQC relevance **5/5**；Formal feasibility **4/5**；Publication potential **5/5**。

**可发表门槛**：至少给出一个通用提升定理、两个不同协议实例和一个旧设计反例。只给 PQXDH 的新 ProVerif model 不够。

### A2. Malicious registration 与多设备目录中的 identity binding

**精确未决问题**

当一个 identity 同时拥有 classical signing key、PQ signing/KEM keys、one-time prekeys、last-resort keys 和多个 device keys 时，何种注册与更新协议保证：任一成功 hybrid session 都绑定到同一逻辑 identity 的一致 key epoch，而不能拼接来自不同 device、epoch、algorithm 或 account 的 component keys？

**为什么现有工作没有解决**

已有 binding 结果主要把 `pk` 当作输入或允许 malicious key generation；它们没有同时建模目录服务器、key transparency、device membership、prekey consumption 和 credential rollover。PQXDH 证明也不等于完整 Signal directory/multi-device 证明。[2][3][5]

**攻击模型**

- **Attacker capability**：`M-server + K-repl + MU`，可选择性返回旧 bundle、混合两个 device 的 keys、隐藏 one-time key 或重放旧 epoch；不能伪造仍安全的签名。
- **Violated property**：`identity binding`、`key freshness`、`cross-session security`、`downgrade resistance`、`auditable forward secrecy`。
- **Minimal attack trace**：服务器向 initiator 返回 `(classical key, device 1, epoch e)` 与 `(PQ key, device 2, epoch e-1)`；两部分各自签名有效，但 bundle 没有一个共同承诺；握手成功后双方对 peer device/epoch 不一致。
- **Required formal model**：带版本和 append-only/rollbackable directory state 的三方模型；bundle-level commitment；linear one-time prekey；device add/remove；corrupt server 但 honest endpoints；目标是 injective agreement on a canonical `CredentialBundleHash`。

**工具适配性**

| 工具 | 适配度 | 用法 |
|---|---:|---|
| Tamarin | 5/5 | 目录状态、epoch、rollback、linear prekey、设备成员变化 |
| ProVerif | 4/5 | bundle substitution 与 correspondence；对全局单调日志需抽象 |
| Squirrel | 3/5 | key transparency 的 indistinguishability/隐私扩展；大状态证明成本高 |
| CryptoVerif/EasyCrypt | 3/5 | bundle commitment 与签名/KEM reduction；不适合完整目录状态 |

**评分**：Novelty **4/5**；PQC relevance **5/5**；Formal feasibility **4/5**；Publication potential **4/5**。

**可发表门槛**：需真实协议 bundle 格式或开源目录实现作为实例；否则容易被评价为一般 PKI/key-transparency 问题，而非 Hybrid PQC 新贡献。

---

## 4. B：Classical/PQC compromise lattice

### B1. Hybrid ratchet 的腐化偏序与精确恢复边界

**精确未决问题**

对于同时维护 classical DH ratchet、PQ sparse ratchet、symmetric chain、identity state 和持久化 session state 的协议，如何定义一个非二元的 freshness/recovery 语义，使每个消息密钥都能回答：

```text
在 C-LT、C-E、C-PQ、C-chain、device clone、state rollback、Q-now/Q-later
的任意时间组合下，哪些过去/当前/未来消息仍保密，何时恢复？
```

目标不是简单枚举 reveal cases，而是建立一个可比较、可机械求值的 compromise lattice；其节点表示攻击者知识集合，边表示腐化、删除、fresh contribution 或 state recovery，输出是每个 message interval 的安全标签。

**为什么现有工作没有解决**

- PQ3、Triple Ratchet、SPQR 等已给出若干 FS/PCS/PQ 保证，但各自使用不同 epoch、communication pattern、state 与腐化假设；它们没有提供跨协议统一的 component-wise lattice。[7][11][13]
- 2025 secure-messaging 比较工作把 bandwidth 与 messaging behavior 纳入 PCS 评价，同时明确 session-handling 的影响仍是开放方向。[12]
- session-to-conversation lifting 研究处理会话管理，但不是面向双 component、量子时间点与 sparse PQ update 的完整 lattice。[14]

**攻击模型**

- **Attacker capability**：`A + C-LT + C-E + C-PQ + S-state + Q-later` 的任意子集；腐化可以瞬时、持续或在特定 epoch 后结束。
- **Violated property**：`forward secrecy`、`post-compromise security`、`future secrecy`、`session-key independence`、`graceful degradation`。
- **Minimal attack trace**：

  1. 在 epoch `e` 泄漏 classical ratchet secret 和当前 symmetric chain，但 PQ state 未泄漏。
  2. 攻击者延迟或丢弃 PQ chunks，使接收方不能完成 PQ update。
  3. 在双方发送新的 DH share 后，经典分量恢复，但 PQ 分量仍处于旧 epoch；或反向发生。
  4. 两个分量的局部“已恢复”定义不同，最终 hybrid message key 的真实恢复点与论文所用单一 epoch 指标不一致。

- **Required formal model**：multiset-rewriting state machine；显式 `Compromise(component,scope,time)`、`Erase`、`FreshContribution`、`Install`、`Clone`、`Rollback` 事件；对每个 message key 计算 dependency DAG，并以 lattice predicate 定义 freshness。需要区分 attacker can read state、control future transitions 和仅持有过去 snapshot。

**工具适配性**

| 工具 | 适配度 | 最适合承担的部分 | 主要限制 |
|---|---:|---|---|
| Tamarin | 5/5 | 时间、状态、删除、乱序、分片、clone/rollback、复杂 compromise rules | 全部组合可能导致 proof search explosion，需按 dependency slice 模块化 |
| ProVerif | 4/5 | 无界 sessions 与自动 secrecy/correspondence；适合先筛选候选协议 | mutable state、rollback 与精确 epoch ordering 表达较绕 |
| Squirrel | 4/5 | 为关键恢复边建立 computational secrecy/PCS 证明；2026 ratchet 工作增强可行性 | 大规模 state lattice 需要人工交互与抽象 |
| CryptoVerif/EasyCrypt | 3/5 | 对选定 lattice 边给出 computational game；证明 hybrid KDF strongest-component 保证 | 不适合直接探索整个异步状态空间 |

**评分**：Novelty **4/5**；PQC relevance **5/5**；Formal feasibility **5/5**；Publication potential **5/5**。

**可发表门槛**：必须产生至少一个现有“恢复时间”指标无法表达的反例，或证明两个协议在旧指标下等价、在新 lattice 下不可比。

### B2. Component compromise 是否真的 graceful degradation

**精确未决问题**

当 PQ component 因 cryptanalysis、side channel 或 key mishandling 泄漏时，能否形式化证明整个 protocol 精确降级为 classical protocol 的安全性；反方向 classical component 被量子攻破时，能否精确降级为 PQ protocol？哪些共享资源会破坏此 non-interference，例如 RNG、KDF state、transcript parser、error channel、key storage 和 retry logic？

**为什么现有工作没有解决**

现有 hybrid proof 多在理想 component API 下证明 strongest-component indistinguishability；implementation attack 则通常停在恢复某个 KEM secret key。二者之间缺少“component leak 不改变另一 component 的控制流、输入分布和身份绑定”的 non-interference 证明。[5][6][16][17]

**攻击模型**

- **Attacker capability**：先获得 `Leak(sk_pq)` 或 `Break(classical)`，再拥有 `A + O-dec + X-mode`。
- **Violated property**：`graceful degradation`、`hybrid robustness`、`key independence`、`authentication`。
- **Minimal attack trace**：利用已泄漏的 PQ key 构造特殊 `ct_pq`，触发 shared parser/retry 分支；该分支改变 transcript 或跳过 classical share 验证，使本应只损失 PQ 分量的事件升级为完整 session compromise。
- **Required formal model**：ideal/real 两层 component contract；标注共享状态与 observable failures；non-interference 或 robust safety lemma：`Leak(PQ)` 后的 trace 投影不得比 standalone classical model 多产生 accept/secret events。

**工具适配性**：Tamarin **4/5**（trace projection）；ProVerif **4/5**（biprocess/observational equivalence）；Squirrel **4/5**（computational non-interference）；CryptoVerif/EasyCrypt **5/5**（game-based degradation theorem）。

**评分**：Novelty **4/5**；PQC relevance **5/5**；Formal feasibility **3/5**；Publication potential **4/5**。

---

## 5. C：Transcript binding 与 migration security

### C1. Hybrid TLS/SSH 的完整 negotiation-to-key transcript invariant

**精确未决问题**

当 endpoint 同时支持 classical、hybrid 和 PQ-only modes 时，是否存在一个端到端 invariant，保证最终 traffic key、认证身份和安全等级同时绑定到：

```text
offered algorithms
selected group / suite
component shares and ciphertexts
retry / fallback reason
protocol version and role
resumption / PSK context
authenticated transcript
```

进一步要求：如果双方共同策略要求 hybrid，active attacker 不能使任一方以 classical 或 incomplete-hybrid state 完成；如果策略允许兼容 fallback，则双方必须对降级原因和最终 security level 达成 agreement。

**为什么现有工作没有解决**

- 现有 hybrid TLS/SSH 计算证明对固定 draft suite 给出强保证，但 TLS 模型明确排除 algorithm negotiation、tickets 和 post-handshake authentication。[8]
- 2026 年 RFC 9954 与 RFC 10024 已把 hybrid TLS 构造和具体 ECDHE–ML-KEM groups 固化为现实研究对象；RFC 10024 也明确警告其分析依赖 TLS transcript，不能直接移植到其他协议。[9][10]
- TLS 1.3 原有 downgrade protection 不等于组织策略层的“hybrid required”，也不自动覆盖 retry、middlebox-induced fallback、resumption mode 或日志/API 对安全等级的误报告。
- Terrapin 证明 SSH transport phase 边界之外的扩展消息可以真实破坏 negotiation integrity，因此只验证 KEX hash 不足。[15]

**攻击模型**

- **Attacker capability**：`A + N-neg + P`；可删除、重排、重放 offered groups、HelloRetryRequest/等价 retry、extension messages 与 fallback signals；可诱导连接中断和重连，但不能伪造仍安全的 Finished/signature。
- **Violated property**：`negotiation integrity`、`downgrade resistance`、`transcript integrity`、`context binding`、`migration security`、HNDL secrecy。
- **Minimal attack trace**：

  1. Client offer `{hybrid, classical}`，本地 policy 为 `hybrid-required` 或 `hybrid-preferred`。
  2. 攻击者删除 hybrid share、诱发 retry，或阻断连接使应用进行未绑定的 classical retry。
  3. Server 完成 classical handshake；Client/app 将第二次连接错误地关联为原 hybrid attempt 的兼容恢复。
  4. 双方 cryptographic transcript 各自有效，但 application-level migration transcript 未记录失败链；HNDL guarantee 被无声降级。

- **Required formal model**：必须跨越单次 handshake。模型包含 policy state、capability cache、connection attempts、retry cause、resumption PSK/ticket、最终 security-level event；定义 `MigrationCommit(peer,attempt_chain,offer,select,reason,level,transcript_hash)`。核心 lemma：同一 logical connection 的 completed level 不低于双方共同 policy，除非双方对 authenticated downgrade reason 显式 agreement。

**工具适配性**

| 工具 | 适配度 | 最适合承担的部分 | 主要限制 |
|---|---:|---|---|
| Tamarin | 5/5 | 多次连接、retry/fallback 状态、policy、ticket、降级 trace、injective agreement | TLS 全状态易爆炸，应先做最小 migration core，再逐项扩展 |
| ProVerif | 4/5 | 自动验证固定/无界 handshakes 的 correspondence 与 secrecy | 跨连接 cache、失败原因和有序 retry 不如 Tamarin 直接 |
| Squirrel | 4/5 | transcript hash、context/domain separation 和 selected suite 的 computational reasoning | 完整 TLS 状态机证明成本高 |
| CryptoVerif/EasyCrypt | 4/5 | 对“已选定 transcript”给 multi-stage AKE 与 PQ secrecy reduction | 不适合自动发现 operational downgrade trace |

**评分**：Novelty **5/5**；PQC relevance **5/5**；Formal feasibility **4/5**；Publication potential **5/5**。

**可发表门槛**：最好同时给出：一个规范/实现层的降级反例、一个 transcript/policy 修复、Tamarin proof，以及对修复后 selected-suite 计算假设的连接。只证明 RFC 字段都进入 TLS transcript 仍不够。

### C2. Resumption、0-RTT 与 key update 的跨阶段 PQ security continuity

**精确未决问题**

一个最初通过 hybrid KEX 建立的连接，在 resumption、0-RTT、PSK-only、post-handshake authentication 或 key update 后，仍能声称何种 PQ security level？该等级是否应继承、衰减或重新获取？

**为什么现有工作没有解决**

固定-suite首次握手 proof 与 KEMTLS multi-stage models 不等于真实 ticket lifecycle。关键空白是把首次 hybrid entropy、ticket encryption key、resumption PSK、认证算法和后续 key update 的依赖关系统一为可审计安全标签。[8]

**攻击模型**

- **Attacker capability**：`P + A + C-LT`，可记录初始与恢复连接，后来腐化 ticket key/PSK 或经典认证 key，并操纵是否执行新 hybrid exchange。
- **Violated property**：`PQ forward secrecy`、`key freshness`、`cross-session security`、`security-level agreement`。
- **Minimal attack trace**：hybrid full handshake 产生 ticket；后续大量 PSK-only resumptions 不注入新 PQ entropy；ticket/PSK 后泄漏使多个被错误标记为“PQ protected”的会话同时失守。
- **Required formal model**：multi-stage AKE + persistent ticket state + security-label propagation；每个 key 记录 dependency set 与 erase/reveal time。

**工具适配性**：Tamarin **5/5**；ProVerif **4/5**；Squirrel **4/5**；CryptoVerif/EasyCrypt **4/5**。

**评分**：Novelty **4/5**；PQC relevance **5/5**；Formal feasibility **4/5**；Publication potential **4/5**。

---

## 6. D：Crypto-agile API 与 cross-protocol hybrid security

### D1. 同一 key material 跨 standalone/hybrid API 的联合 oracle security

**精确未决问题**

现实 crypto-agile library 允许同一账户、certificate 或 hardware key 被多个 protocol/mode 调用时，什么是足以覆盖下列联合接口的 hybrid security 定义？

```text
Hybrid.Decap(component_tuple)
Standalone.Decap(component_i)
ProtocolA.Export/Confirm
ProtocolB.Error/Retry
KeyImport / KeyDerive / PrivateToPublic
```

攻击者可在一个 mode 中提交由另一 mode 输出、截取或变形的 component ciphertext。目标是即使一个 component 已失守，另一个 component 的 secrecy、binding 与认证也不因额外 oracle 失效。

**为什么现有工作没有解决**

- 2026 extended hybrid KEM 工作已经指出“combined key 与 ingredient key 独立”的传统假设不现实，并给出更强模型；因此简单重做该模型没有新颖性。[6]
- 尚未闭合的是 protocol-facing API：key usage policy、serialization、error channel、exporter、version dispatch、hardware-backed key 与并发调用并不在纯 KEM oracle 中。
- 2026 combined-KEM binding 分析推进了 real-world combiner binding，但仍没有覆盖一个 library 在多协议、多模式下的身份、状态与错误语义。[5]

**攻击模型**

- **Attacker capability**：`X-mode + O-dec + A + C-one-component`；可选择 API endpoint、algorithm identifier、serialization 和 malformed input；可观察返回值、错误类别与是否继续握手。
- **Violated property**：`extended hybrid IND-CCA`、`cross-protocol security`、`API misuse resistance`、`graceful degradation`、`KEM contribution binding`。
- **Minimal attack trace**：

  1. 系统为同一 logical key handle 启用 `ML-KEM standalone` 与 `X25519+ML-KEM hybrid`。
  2. 攻击者截取 hybrid `ct_pq`，通过 standalone API decapsulate，或把 standalone 输出包装进 hybrid request。
  3. API 的后处理 label、failure behavior 或 authorization policy 不同，泄露相关 key/failure bit。
  4. 攻击者把结果用于区分 hybrid challenge、制造 accepted incomplete hybrid session，或将 contribution 绑定到错误 protocol identity。

- **Required formal model**：typed multi-oracle game 与 API transition system。每个 key handle 带 `(algorithm, mode, protocol, role, epoch, usage)` policy；serialization/dispatch 是显式函数；错误可观察。需要证明 reference monitor/type system 对危险 oracle path 的不可达性，或证明带 domain-separated post-processing 的联合安全归约。

**工具适配性**

| 工具 | 适配度 | 最适合承担的部分 | 主要限制 |
|---|---:|---|---|
| Tamarin | 4/5 | API 调用图、key lifecycle、policy bypass、accepted incomplete-hybrid trace | IND-CCA 与概率型 oracle indistinguishability 只能抽象 |
| ProVerif | 5/5 | 多 channel/API 自动攻击搜索、类型混淆与 correspondence | 精确 mutable handles、错误概率和资源 aliasing 有限制 |
| Squirrel | 4/5 | 跨 protocol context 的 computational equivalence、domain separation | 复杂 library state 需较多手工建模 |
| CryptoVerif/EasyCrypt | 5/5 | 联合 oracle game、post-processing、key reuse 和 reduction | 不负责真实语言 API 的 aliasing/FFI/错误实现 |

**评分**：Novelty **4/5**；PQC relevance **5/5**；Formal feasibility **4/5**；Publication potential **5/5**。

**可发表门槛**：应选一个真实库或标准 API，抽取可执行调用图，并给出至少一个现有 API 允许、修复 API 阻止的 cross-mode trace。只有新安全游戏而无真实接口，投稿系统安全 venue 的说服力不足。

### D2. Misuse-resistant typed hybrid API 与 proof-carrying security level

**精确未决问题**

能否让 API 的类型与返回值强制表示：“两个 component 已验证、属于同一 suite/transcript/peer，当前安全等级为 hybrid/classical/PQ-only/failure”，从而使应用不能忽略一个 component failure、不能把 standalone key 标成 hybrid，也不能在未完成 binding 前导出 traffic key？

**为什么现有工作没有解决**

安全标准与 KEM proof 通常假设调用方正确组合输入；现实 API 往往只返回 bytes 或通用 success/failure。缺少从 cryptographic preconditions 到语言类型、状态 token 与日志/telemetry 的 refinement。

**攻击模型**

- **Attacker capability**：`A` 结合 developer/API misuse；发送 malformed/missing share，诱发部分成功路径。
- **Violated property**：`API misuse resistance`、`negotiation integrity`、`key confirmation`、`security-level agreement`。
- **Minimal attack trace**：PQ decapsulation failure；wrapper 捕获错误后继续使用 classical `ss_c`；函数仍返回裸 `traffic_key`，上层记录为 hybrid success。
- **Required formal model**：typestate 或 linear capabilities：只有持有 `Bound<Classical,PQ,Transcript,Peer>` proof token 才能调用 `DeriveTrafficKey`；错误路径没有该 token。连接 F*/Rust typestate 与协议事件。

**工具适配性**：Tamarin **4/5**（token protocol）；ProVerif **4/5**；Squirrel **3/5**；CryptoVerif/EasyCrypt **4/5**；F*/hax/Creusot/Prusti 是实现部分的必要补充。

**评分**：Novelty **4/5**；PQC relevance **5/5**；Formal feasibility **4/5**；Publication potential **4/5**。

---

## 7. E：Symbolic model 与 implementation gap

### E1. Compiler-aware leakage contract 与协议级组合

**精确未决问题**

如何把 binary-level constant-time、memory safety、panic-freedom、secret erasure 与 fault analysis 的结论，转换为 Tamarin/ProVerif/Squirrel 可以消费的 component contract，并证明：

```text
implementation evidence
⇒ allowed leakage events only
⇒ protocol theorem under those leakages
⇒ precise graceful degradation result
```

contract 不能只有 `secure/insecure` 二值，而应表示攻击者可观察 timing class、failure bit、部分 secret、完整 component key 或 state rollback 中的哪一种。

**为什么现有工作没有解决**

- KyberSlash 与 HQC timing attack 表明编译器/平台可把理想 `Decap` 变成 key-recovery oracle，但协议 proof 通常只把 KEM 当作原子函数。[16][17]
- SPQR 的 2026 工作把 hand-written ProVerif model、Rust-to-F* runtime safety 与实现放入同一 artifact，是重要进展；但 panic-freedom/functional correctness 不是 binary constant-time、fault security 或自动的 protocol refinement。[13]
- 现有方法缺少统一、可审计的 evidence boundary：哪些 implementation proof 足以删除某个 `Leak` rule，哪些只能缩小其能力。

**攻击模型**

- **Attacker capability**：`O-dec + S-ch + fault + A`；能提交选择 ciphertext，观察 timing/cache/error，或诱发特定 fault；网络能力可利用泄漏结果继续 protocol attack。
- **Violated property**：`side-channel resistance`、`KEM key secrecy`、`hybrid robustness`、`graceful degradation`、`PCS`。
- **Minimal attack trace**：

  1. 攻击者向 hybrid endpoint 发送自适应 `ct_pq` 并测量 decapsulation。
  2. binary analysis/实测表明观察值泄漏 predicate `b_i(sk_pq,ct_i)`；重复查询恢复 `sk_pq`。
  3. 协议模型触发 `LeakComponent(PQ,sk_pq,t)`，而不是无条件泄漏整个 session。
  4. 攻击者再操纵 transcript、retry 或未来 `Q-later`，检查整体是按预期降级，还是连带破坏 identity/另一 component。

- **Required formal model**：

  - implementation 层：编译后二进制或 verified assembly 的 observational trace；
  - contract 层：`LeakNone / LeakPredicate / LeakFailure / LeakKey / FaultedOutput`；
  - protocol 层：带时间和 component scope 的 multiset-rewriting；
  - refinement：每个实现 trace 可映射到 contract trace，进而由 protocol theorem 覆盖。

**工具适配性**

| 工具 | 适配度 | 最适合承担的部分 | 主要限制 |
|---|---:|---|---|
| Tamarin | 4/5 | 消费 leak/fault events，分析后续 protocol consequence 与 compromise timing | 不能自行证明 binary constant-time，也难表达定量 timing distribution |
| ProVerif | 4/5 | faulted decap、error oracle 和泄漏后的自动攻击链 | stateful query budget、时间顺序和部分泄漏精度受限 |
| Squirrel | 4/5 | observational equivalence 与 computational leakage assumptions | 需要扩展或手工证明 implementation contract 的 soundness |
| CryptoVerif/EasyCrypt | 4/5 | leakage-resilient game、faulty oracle 与 graceful-degradation reduction | binary/编译器 refinement 需外部工具 |

**评分**：Novelty **5/5**；PQC relevance **5/5**；Formal feasibility **2/5**；Publication potential **5/5**。

**可发表门槛**：建议先限制到一个 leakage class、一个 ML-KEM implementation 和一个 hybrid protocol。试图一次覆盖所有 side channels 会失控。即便只完成 `timing-key-recovery contract → hybrid TLS consequence theorem`，也可能形成强论文。

### E2. Decapsulation failure、retry 与 state consistency

**精确未决问题**

当 KEM 使用 implicit rejection 时，protocol 如何保证合法 ciphertext、invalid ciphertext、伪随机 failure key、parser failure、timeout 和 retry 在外部行为上满足所需 equivalence，并且不会导致一方安装 hybrid key、另一方重试 classical mode 或双方推进到不同 epoch？

**为什么现有工作没有解决**

primitive IND-CCA 把 decapsulation 行为封装在安全游戏中；protocol proof 又通常使用理想 `decap`。真实实现中的错误分类、日志、计时、重传和状态提交时刻跨越 KEM、transport 与应用层，未被任一层单独覆盖。

**攻击模型**

- **Attacker capability**：`A + O-dec + S-state`；能发送 malformed/related ciphertext、丢包、触发 timeout 并观察 retry mode、错误、连接状态或 timing。
- **Violated property**：`decapsulation-failure handling`、`state consistency`、`key confirmation`、`downgrade resistance`、`replay resistance`。
- **Minimal attack trace**：修改 `ct_pq`；receiver 得到 implicit-rejection key 并在确认前推进 epoch；sender timeout 后重试旧/经典路径；攻击者重放旧 confirmation，使双方在不同 component state 下各自 accept。
- **Required formal model**：显式 tentative/committed key state、failure-key non-acceptance、retry budget、timeout、rollback 与 confirmation；另外用 observational equivalence 检查 failure classes 是否可区分。

**工具适配性**：Tamarin **5/5**；ProVerif **4/5**；Squirrel **4/5**；CryptoVerif/EasyCrypt **4/5**。

**评分**：Novelty **4/5**；PQC relevance **5/5**；Formal feasibility **3/5**；Publication potential **4/5**。

### E3. Hybrid PCS 的 session-to-conversation lifting

**精确未决问题**

对包含 SPQR/Triple Ratchet 的真实 conversation，session replacement、device clone、state loss、backup restore 与并发 device delivery 是否保持 protocol-level PQ FS/PCS；如果不保持，恢复条件应如何修改？

**为什么现有工作没有解决**

session-handling lifting 已经证明“session 安全”不能直接等于“conversation 安全”；2025 bandwidth/PCS 比较工作也明确把 session-handling 影响留作开放问题。SPQR 2026 进一步缩小 code/model gap，但不意味着所有上层 conversation、multi-device、backup 和 rollback 语义均已证明。[12][13][14]

**攻击模型**

- **Attacker capability**：`S-state + M-server + A`；克隆设备 snapshot、延迟某设备 PQ chunks、触发 session replacement 或恢复旧 backup。
- **Violated property**：`PCS`、`state consistency`、`injective agreement`、`clone detection`、`cross-session security`。
- **Minimal attack trace**：从已腐化 snapshot 克隆 device；原设备完成 PQ heal，但服务器继续向 clone 投递/接收；conversation 层错误合并两条 session，导致攻击者维持未来消息访问或注入。
- **Required formal model**：conversation graph、device membership、session identifiers、delivery server、state clone/rollback；将底层 ratchet guarantee 作为条件化接口而非重建全部密码学。

**工具适配性**：Tamarin **5/5**；ProVerif **4/5**；Squirrel **3/5**；CryptoVerif/EasyCrypt **2/5**。

**评分**：Novelty **3/5**；PQC relevance **5/5**；Formal feasibility **4/5**；Publication potential **4/5**。

---

## 8. Top 5 research directions

### Top 1 — Hybrid TLS/SSH migration transcript 与 downgrade resistance

**Research problem**  
定义并验证跨 initial handshake、retry/fallback、resumption、0-RTT 和扩展协商的 `Migration Transcript Agreement`：双方不仅同意 cryptographic transcript，还同意共同能力、策略、降级原因与最终 PQ security level。

**Why it is not solved**  
固定 hybrid suite 的 KEX/AKE proof 不包含完整协商生命周期；RFC 9954/10024 已给出现实构造，但标准文本本身不是对应用 retry policy、ticket lifecycle 和多次连接的机器证明。[8][9][10] 原有 TLS downgrade sentinel 也没有表达“组织策略要求 hybrid”的跨连接约束。

**Possible contribution**

1. 新安全定义：`policy-aware migration agreement` 与 `no-silent-downgrade`。
2. TLS 或 SSH 的最小迁移状态机，并对真实 RFC/实现行为作映射。
3. 至少一个旧 wrapper、fallback policy 或 resumption 路径的攻击 trace。
4. 修复设计：authenticated downgrade reason、attempt-chain binding 或 security-level token。
5. 修复后的 Tamarin proof 与 selected-suite computational assumption mapping。

**Attack model**  
`A + N-neg + connection blocking + ticket/PSK reveal after completion + Q-later`。攻击者不能伪造 Finished，但可利用应用层重连、缓存和 fallback；挑战是让各次握手单独合法而逻辑连接整体被降级。

**Formal verification plan**

1. Phase 1：Tamarin 建模 `{offer, select, policy, retry, fallback, ticket, resume, level}`，先找最小反例。
2. Phase 2：加入 explicit `MigrationCommit`/`MigrationRunning` events，证明 non-injective 与 injective agreement。
3. Phase 3：将 transcript hash、KDF label 与 suite 选择在 Squirrel 或 CryptoVerif 中抽象为 computationally sound assumptions。
4. Phase 4：对 OpenSSL/BoringSSL/OpenSSH 风格 wrapper 做 trace instrumentation，检查模型中的 attempt chain 是否与实现一致。
5. Phase 5：公开模型、攻击 replay、版本/配置 manifest 与 proof coverage table。

**Expected paper contribution**  
首个覆盖“固定 hybrid KEX 之外迁移生命周期”的端到端形式化结果；若找到实际 silent fallback 或 security-level misreport，目标可达 USENIX Security/CCS/NDSS。若只有规范模型与修复 proof，更适合 CSF/EuroS&P。

---

### Top 2 — KEM binding 到 protocol identity/contribution agreement 的提升框架

**Research problem**  
确定哪一组 primitive binding notions、combiner inputs 与 credential/transcript conditions 足以推出 hybrid AKE 的 identity binding、UKS resistance、session independence 和 injective contribution agreement。

**Why it is not solved**  
primitive 与 combined-KEM binding 已成为独立研究线，具体协议也已有 PQXDH `SH-CR` 经验；缺少的是二者之间可复用、可实例化的 abstraction theorem。[2][3][4][5] 现有 IND-CCA/hybrid robustness 只回答 key indistinguishability，不回答“该 key 属于哪个身份、设备、suite 和会话”。

**Possible contribution**

1. `Protocol Contribution Binding` 游戏或 trace property。
2. 从 `HON/MAL/LEAK-BIND + combiner context binding + credential agreement` 到 AKE property 的提升定理。
3. 自动生成或检查协议必须绑定的字段集合。
4. 在 PQXDH-like、TLS-like 和一个 directory/multi-device protocol 上实例化。
5. 给出一个满足 IND-CCA 但违反 protocol contribution binding 的 separation example。

**Attack model**  
`A + K-repl + malicious registration + one-component compromise + MU`；允许攻击者选择 malformed but accepted keys、重用 ciphertext、交换 key-id/credential owner，并在多个会话中寻找同 secret 的不同归属。

**Formal verification plan**

1. EasyCrypt/CryptoVerif 定义 primitive 与 combiner games，证明或假设实例化条件。
2. ProVerif 自动搜索 key/identity misbinding traces，快速验证定义是否排除已知反例。
3. Tamarin 建恶意注册、key epoch、linear prekey 与 injective agreement。
4. Squirrel 尝试证明 symbolic constructor abstraction 对选择的 computational binding assumptions 健全。
5. 对 ML-KEM、HQC 或 X-Wing 给一个正实例，对弱/错误组合给负实例。

**Expected paper contribution**  
把快速发展的 KEM binding 理论提升为 protocol-design rule 和可机械验证框架；如果 abstraction theorem 与多个真实协议实例都完成，适合 CRYPTO/EUROCRYPT 的 protocol track、CSF 或 IEEE S&P。若以攻击和自动检测为主，更适合 USENIX Security/CCS。

---

### Top 3 — Crypto-agile API 的 cross-mode hybrid security

**Research problem**  
对同一 key handle 被 standalone、hybrid 和多个 protocol 调用的场景，定义联合 oracle security，并设计 misuse-resistant API，阻止 component ciphertext、failure output 和 security label 跨模式穿透。

**Why it is not solved**  
extended hybrid KEM 已覆盖比传统 combiner 更强的 ingredient/combined decapsulation access，但没有覆盖真实 API 的 serialization、authorization、error、export、aliasing、FFI 与 protocol identity。[6] 现实风险恰恰发生在这些 dispatch 边界，而不是抽象 `Decap` 函数内部。

**Possible contribution**

1. 从一个开源 crypto provider 抽取 key-handle 与 dispatch semantics。
2. 定义 `API-extended hybrid CCA/binding` 游戏。
3. 发现 cross-mode oracle、partial-success 或 security-label confusion trace；若无现存漏洞，构造可复现 misuse benchmark。
4. 提出 domain-separated post-processing、key-usage separation 与 typestate API。
5. 证明修复 API 实现联合安全或危险路径不可达。

**Attack model**  
`X-mode + O-dec + malformed serialization + one-component compromise`；攻击者通过网络间接或本地 API 直接选择 mode 与 algorithm identifier，并观察 bytes、errors、timing category 和 state transition。

**Formal verification plan**

1. ProVerif 表达多 API channels 与 key alias，自动找 cross-mode trace。
2. Tamarin 表达 persistent key handles、usage policy、并发调用和 stateful authorization。
3. EasyCrypt/CryptoVerif 建联合 oracle reduction，连接 split-key PRF/post-processing 条件。
4. F*/Rust typestate 或轻量 reference monitor 实现 proof-carrying `HybridAccepted` token。
5. differential tests 验证错误/日志/security label 与模型一致。

**Expected paper contribution**  
首个面向真实 crypto-agile library 的 hybrid KEM API 安全模型、攻击面和 verified mitigation。真实漏洞可支撑 USENIX Security/CCS；无漏洞但有通用 API theorem 与 artifact，则适合 CSF/EuroS&P/ACM TOPS。

---

### Top 4 — Hybrid ratchet compromise lattice 与 recovery semantics

**Research problem**  
建立同时覆盖 classical、PQ、symmetric、identity 与 persistent state 的腐化 lattice，并由消息依赖关系机械计算每条消息在任意 compromise timeline 下的 FS/PCS/PQ security 与恢复时刻。

**Why it is not solved**  
现有 ratchet work 的 epoch、bandwidth、messaging behavior 和 corruption definitions 不统一；session-handling、state loss 与 conversation lifting 又属于另一研究线。[7][11][12][13][14] 因此“协议 A 比协议 B 恢复快”在 device clone、丢包、PQ chunk delay 或只腐化一个 component 时没有统一含义。

**Possible contribution**

1. 偏序化 compromise/recovery semantics，而非二元 fresh/not-fresh。
2. 从 protocol trace 自动生成 message-key dependency DAG 和 vulnerable interval。
3. 对 PQ3-like、Triple Ratchet/SPQR-like 两类协议作不可比性或 dominance 证明。
4. 找到旧 epoch metric 无法表达的 attack/longer recovery trace。
5. 给协议设计者一个 recovery regression suite。

**Attack model**  
`C-LT/C-E/C-PQ/C-chain/S-state/Q-later` 可在不同时间发生；攻击者还可控制网络、延迟 PQ chunks、克隆 snapshot，并在某时刻停止主动控制以测试 healing。

**Formal verification plan**

1. Tamarin 建立 component-scoped reveal、erase、install、clone、rollback 和 chunk-delivery rules。
2. 先验证有限 component lattice 的 sanity lemmas，再扩展无界 sessions。
3. 用 ProVerif 快速筛选候选 protocol variants 与 secrecy queries。
4. 用 Squirrel 对一到两个关键 healing transitions 给 computational secrecy proof。
5. 将 USENIX 2025 的 communication-pattern metric 扩展为 state/session-aware vulnerable-message metric。

**Expected paper contribution**  
统一 hybrid secure messaging 的 compromise vocabulary、形式语义和比较方法；若产生新 protocol variant 或真实部署反例，可投 USENIX Security/CCS。以理论比较和机器证明为主时，CSF/EUROCRYPT 更匹配。

---

### Top 5 — Compiler-aware leakage contract 与 hybrid graceful degradation

**Research problem**  
证明某个 PQ KEM implementation 的可观察行为可以被一个精确 leakage contract 模拟，再证明在该 contract 下 hybrid protocol 是否仍只降级到 classical security，而不会因 error、retry、parser 或 state coupling 全面失守。

**Why it is not solved**  
implementation attacks 证明了 component key 可被恢复；protocol proof 假设理想 primitive。SPQR 等最新工作缩短源码与 protocol model 距离，但 runtime safety/functional correctness 仍不自动给出 binary constant-time 或 side-channel-aware protocol theorem。[13][16][17]

**Possible contribution**

1. 一个有限、可复用的 `LeakageContract` 语言。
2. 对选定 ML-KEM implementation 的 binary/measurement evidence。
3. implementation trace 到 contract trace 的 refinement。
4. hybrid TLS/SSH/ratchet 在 `Leak(PQ)`、`LeakPredicate`、`FaultedOutput` 下的 Tamarin/CryptoVerif theorem。
5. 一个展示“只泄漏 PQ key”与“共享 failure path 导致整体失守”差异的负实例。

**Attack model**  
`chosen ciphertext + timing/cache/fault observation + active network + Q-later`。查询预算、噪声和平台必须固定；协议后果模型只能使用实现层实际证明可获得的 leakage，不能任意强化。

**Formal verification plan**

1. 选定单一实现/编译器/architecture，复现已知 timing class 或证明 constant-time。
2. 把结果编译为 `LeakNone/LeakPredicate/LeakKey/FaultedOutput` contract。
3. Tamarin 分析 leak 后的身份、状态与时间后果。
4. CryptoVerif/EasyCrypt 证明仍安全分量的 key indistinguishability 与最终 KDF degradation。
5. 用反例驱动 contract refinement；全部 artifact 固定 compiler flags、binary hash、模型 hash 与测试 traces。

**Expected paper contribution**  
真正连接 PQ implementation verification 与 hybrid protocol proof 的跨层方法。难度最高，但若完成 refinement theorem 与真实实例，具备 USENIX Security/CCS/IEEE S&P 潜力；若只完成方法原型，CSF/FSE/TCHES 更现实。

---

## 9. 选题决策建议

| 研究条件 | 首选 | 原因 |
|---|---|---|
| 希望 6–12 个月形成第一篇完整论文 | C1 migration transcript 或 B1 compromise lattice | 可先用 Tamarin 得到反例/定理，再逐步增加 computational 层 |
| 密码学归约能力强，偏 CRYPTO/EUROCRYPT/CSF | A1 binding-to-AKE 或 D1 joint-oracle API | 核心贡献可以是新定义与 reduction，不依赖发现现网漏洞 |
| 系统/实现能力强，有 binary/side-channel 工具经验 | E1 leakage contract | 风险最高，但跨层贡献和实际影响最大 |
| 能接触真实 library 或 protocol maintainer | D1/C1 | 真实调用图、配置与修复验证会显著提高 Publication potential |
| 只有 Tamarin/ProVerif 经验，暂时没有 computational proof 能力 | B1 或 C1 的 symbolic core | 仍可形成强 trace/state 工作，但应邀请 computational/implementation 合作者补齐边界 |

### 最稳妥的研究路线

推荐先做 **C1 的最小 migration core**，同时把 A1 作为可复用理论层：

```text
第 1 阶段：TLS hybrid-required / preferred / fallback 三策略的 Tamarin model
第 2 阶段：寻找跨连接 silent downgrade；定义 MigrationCommit events
第 3 阶段：把 pk/ct/suite/identity contribution binding 加入 agreement 参数
第 4 阶段：连接 RFC 9954/10024 与一个开源 TLS wrapper
第 5 阶段：补 selected-suite computational argument 与 artifact provenance
```

这条路线的优点是：即使没有发现实现漏洞，也能产出新的 migration property 与机器证明；若发现真实 fallback、security-level misreport 或 resumption 问题，论文影响力会显著提升。

### 高风险高回报路线

E1 最适合作为博士主线而非第一篇短周期论文。应先把研究范围固定为：

```text
一个 ML-KEM implementation
+ 一个 compiler/architecture
+ 一个 leakage class
+ 一个 hybrid TLS/SSH handshake
+ 一个 graceful-degradation theorem
```

超过这一范围会同时陷入编译器验证、统计 side-channel、KEM reduction 与协议状态爆炸。

---

## 资料来源

1. [Hybrid PQC Protocol Security Research Map](./hybrid-pqc-security-research-map.md)，本分析的本地证据底座，2026-09-09。
2. Karthikeyan Bhargavan, Charlie Jacomme, Franziskus Kiefer, Rolfe Schmidt. “[Formal Verification of the PQXDH Post-Quantum Key Agreement Protocol for End-to-End Secure Messaging](https://www.usenix.org/conference/usenixsecurity24/presentation/bhargavan).” USENIX Security 2024.
3. Cas Cremers, Alexander Dax, Niklas Medinger. “[Keeping Up with the KEMs: Stronger Security Notions for KEMs](https://eprint.iacr.org/2023/1933).” IACR ePrint 2023/1933.
4. Juliane Krämer, Patrick Struck, Maximiliane Weishäupl. “[Binding Security of Implicitly-Rejecting KEMs and Application to BIKE and HQC](https://eprint.iacr.org/2024/1233.pdf).” IACR Communications in Cryptology 2(2), 2025.
5. Juliane Krämer, Patrick Struck, Maximiliane Weishäupl. “[Binding Security of Combined KEMs: An Analysis of Real-World KEM Combiners](https://eprint.iacr.org/2025/1416).” SCN 2026.
6. Lise Millerjord, Douglas Stebila, Camryn Steckel. “[Split-key PRFs and Extended Hybrid Security for KEM Combiners](https://www.douglas.stebila.ca/research/papers/CIC-MilSteSte26/).” IACR Communications in Cryptology 2(4), 2026.
7. Felix Linker, Ralf Sasse, David Basin. “[A Formal Analysis of Apple’s iMessage PQ3 Protocol](https://www.usenix.org/conference/usenixsecurity25/presentation/linker).” USENIX Security 2025.
8. Bruno Blanchet, Charlie Jacomme. “[Post-Quantum Sound CryptoVerif and Verification of Hybrid TLS and SSH Key-Exchanges](https://bblanche.gitlabpages.inria.fr/publications/BlanchetJacommeCSF24.pdf).” IEEE CSF 2024.
9. Douglas Stebila, Scott Fluhrer, Shay Gueron. “[Hybrid Key Exchange in TLS 1.3](https://www.rfc-editor.org/rfc/rfc9954.html).” RFC 9954, 2026.
10. Kris Kwiatkowski, Panos Kampanakis, Bas Westerbaan, Douglas Stebila. “[Post-Quantum Traditional Hybrid Key Agreement Mechanisms for TLS 1.3](https://www.rfc-editor.org/rfc/rfc10024.html).” RFC 10024, 2026.
11. Yevgeniy Dodis, Daniel Jost, Shuichi Katsumata, Thomas Prest, Rolfe Schmidt. “[Triple Ratchet: A Bandwidth Efficient Hybrid-Secure Signal Protocol](https://doi.org/10.1007/978-3-031-91101-9_11).” EUROCRYPT 2025.
12. Benedikt Auerbach, Yevgeniy Dodis, Daniel Jost, Shuichi Katsumata, Rolfe Schmidt. “[How to Compare Bandwidth Constrained Two-Party Secure Messaging Protocols](https://www.usenix.org/conference/usenixsecurity25/presentation/auerbach).” USENIX Security 2025.
13. Karthikeyan Bhargavan, Maxime Buyse, Graeme Connell, Franziskus Kiefer, Rolfe Schmidt. “[A Formal Analysis of Signal’s Sparse Post-Quantum Ratchet Protocol and its Implementation](https://www.sigsac.org/ccs/CCS2026/program/accepted-papers.html).” ACM CCS 2026, accepted；[artifact](https://luneresearch.com/papers/0db36a85-6fa1-4e7d-9aef-e85df4db083c)。
14. Cas Cremers, Charlie Jacomme, Aurora Naska. “[Formal Analysis of Session-Handling in Secure Messaging: Lifting Security from Sessions to Conversations](https://www.usenix.org/conference/usenixsecurity23/presentation/cremers-session-handling).” USENIX Security 2023.
15. Fabian Bäumer, Marcus Brinkmann, Jörg Schwenk. “[Terrapin Attack: Breaking SSH Channel Integrity by Sequence Number Manipulation](https://www.usenix.org/conference/usenixsecurity24/presentation/b%C3%A4umer).” USENIX Security 2024.
16. Daniel J. Bernstein et al. “[KyberSlash: Exploiting Secret-Dependent Division Timings in Kyber Implementations](https://eprint.iacr.org/2024/1049.pdf).” TCHES 2025.
17. Robin Leander Schröder, Stefan Gast, Qian Guo. “[Divide and Surrender: Exploiting Variable Division Instruction Timing in HQC Key Recovery Attacks](https://www.usenix.org/system/files/usenixsecurity24-schroder.pdf).” USENIX Security 2024.
18. Cas Cremers, Caroline Fontaine, Charlie Jacomme. “[A Logic and an Interactive Prover for the Computational Post-Quantum Security of Protocols](https://eprint.iacr.org/2022/401.pdf).” IEEE S&P 2022.
19. David Baelde, Antoine Dallon, Stéphanie Delaune, Charlie Jacomme, Adrien Koutsos. “[Robust Logical Foundations for Mechanizing Post-Quantum Cryptography in Squirrel](https://www.sigsac.org/ccs/CCS2026/program/accepted-papers.html).” ACM CCS 2026, accepted.

---

## 最终选择

如果只选择一个方向，推荐 **C1：Hybrid TLS/SSH migration transcript 与 downgrade resistance**。它在 Novelty、PQC relevance、Formal feasibility 与 Publication potential 之间最平衡，并且已有 2026 RFC 作为稳定协议对象，却仍存在固定-suite proof 与真实 migration lifecycle 之间的明确证据断层。

如果选择一个长期博士主线，推荐把 **A1 + C1 + D1** 组织为同一研究计划：

```text
KEM contribution binding
        ↓
protocol identity / transcript agreement
        ↓
crypto-agile API enforcement
        ↓
full migration security
```

E1 可作为后期高影响扩展；B1 则适合作为并行的 secure-messaging 分支。


