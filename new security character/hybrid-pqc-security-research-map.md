# Hybrid PQC Protocol Security Research Map（2020–2026）

> 研究截止日：2026-09-09。主线只采用论文、正式会议页面和 IACR/作者公开稿；标准草案只用于说明协议对象，不作为安全结论的主要证据。本文中的“已证明”始终限定于论文给出的模型、腐化时序和算法套件。

## 执行摘要

混合迁移不是把 `ECDH` 换成 `ECDH || ML-KEM` 这么简单。它把一个密钥交换变成了一个**关系型系统**：多个公钥、密文、共享秘密、身份、算法标识、会话角色和 transcript 必须彼此绑定；多个失败、腐化与量子化时间点也必须被同时定义。由此新增的核心风险不是“某个 PQC 算法本身不安全”，而是：

1. **组合器安全不蕴含协议安全**：KDF 能隐藏一个仍安全的分量，不代表公钥/密文绑定、实体认证、协商完整性或密钥确认成立。
2. **IND-CCA 不蕴含贡献绑定**：PQXDH 的 re-encapsulation 反例说明，一个标准 KEM 可以满足 IND-CCA，却允许已知某个私钥的攻击者把同一共享秘密重新绑定到另一公钥/密文；论文因此提出 `SH-CR`（session-key–public-key/ciphertext binding）一类额外性质。[7]
3. **“最强分量安全”需要条件**：只有在分量输出、分量密文/公钥、协议上下文和算法标识被正确输入 KDF/签名 transcript，并且密钥/API 不跨模式泄漏时，才能谈 robust hybrid 或 graceful degradation。[1][2][3][4]
4. **后量子保密与后量子认证是两条轴**：混合 TLS/SSH 可以在“握手期间只有经典攻击者、以后才出现量子攻击者”的模型下证明 HNDL/后量子前向保密，但若认证签名仍是经典的，就不能据此宣称抵抗在线量子冒充。[5][6]
5. **形式模型边界本身就是攻击面**：已验证的混合 TLS 模型显式不含算法协商、resumption ticket 和 post-handshake authentication；PQ3 的 injective agreement 又依赖未建模的会话管理假设。把这些结果泛化为“完整部署已验证”是不成立的。[5][9]
6. **实现层会击穿抽象 KEM**：KyberSlash 与 HQC 的除法计时攻击把“合法/非法密文处理”变成明文检查或密钥恢复 oracle；符号模型里的原子 `decap` 并不覆盖编译器生成的变量时间除法。[18][19]

因此，最有研究价值的对象不是再证明一个 `secrecy` lemma，而是建立下列闭环：

`分量安全游戏 → 组合器 → 带身份/协商的协议 → 状态机与腐化时间线 → 可执行实现与侧信道`。

---

## 0. 研究方法、术语与证据等级

### 0.1 Hybrid、PQC-only 与迁移安全

- **Hybrid KEX/KEM**：同一会话同时使用经典与 PQ 分量，目标通常是“任一分量仍安全则会话密钥安全”。
- **PQC-only**：只用 PQ KEM/签名；减少组合复杂度，但把风险集中到较新的算法、实现与证书生态。
- **Migration security**：不仅关心最终套件，还关心双栈并存、算法协商、回退、旧密钥/证书复用、版本切换和跨模式 API。
- **HNDL（harvest now, decrypt later）**：攻击者现在被动记录，未来获得量子能力；它不同于握手当时已能量子计算的在线攻击者。

### 0.2 证据等级

| 标签 | 含义 | 能支持的结论 | 不能自动支持的结论 |
|---|---|---|---|
| `CP` | 计算安全归约/游戏证明 | 在明确假设与查询接口下的不可区分性、认证或 AKE 安全 | 实现恒定时间、未建模协商、真实状态机 |
| `PQ-CP` | 对 QPT/量子攻击者计算健全 | 论文所给量子接口下的 PQ 保证 | QROM（若工具/论文明确排除）、量子网络消息、侧信道 |
| `SYM` | Tamarin/ProVerif 符号验证 | 无界会话的 trace/correspondence、腐化与状态逻辑 | 概率失败、具体安全界、侧信道、编译器行为 |
| `CODE` | 源码/可执行模型验证 | 抽象与实现之间更短的距离 | 硬件泄漏、编译器优化、部署配置（除非纳入） |
| `ATTACK` | 真实或可执行攻击 | 给定平台/能力下确实可破坏性质 | 所有实现或所有套件均受影响 |
| `GAP` | 论文显式排除或本调研未找到闭环证据 | 可形成研究问题 | 不能等同“已证不安全” |

### 0.3 攻击者能力词表

| 代码 | 能力 |
|---|---|
| `P` | 被动记录消息/密文/transcript |
| `A` | Dolev–Yao 网络控制：截获、修改、重放、乱序、注入 |
| `Q-now` / `Q-later` | 握手当时/未来才获得量子计算能力 |
| `C-LT` | 获得长期身份或静态解密私钥 |
| `C-E` | 获得经典临时 DH 私钥 |
| `C-PQ` | 获得 PQ prekey/KEM 私钥或某分量共享秘密 |
| `O-dec` | 自适应选择密文并观察 decapsulation 输出、错误或时间 |
| `K-repl` | 替换公钥、key-id、prekey bundle 或目录记录 |
| `N-neg` | 修改版本、算法列表、fallback 标志或扩展顺序 |
| `X-mode` | 让同一密钥/API 同时在 hybrid 与 standalone、不同协议或角色中使用 |
| `S-ch` | 观察时间、缓存、功耗、故障或共核 SMT 泄漏 |
| `S-state` | 回滚、克隆、丢失、并发竞争或破坏会话/ratchet 状态 |
| `M-server` | 控制密钥目录、prekey server、服务网络或中间网络实体 |
| `MU` | 多用户、多目标、并发会话和自适应腐化 |

---

# 第一部分：Hybrid PQC 新增的安全挑战

## 1.1 从传统协议到混合/PQC-only，结构发生了什么

### A. 单一 DH/RSA 秘密 → 多个 key material

`ECDH secret`  
↓ 变为 `ECDH secret + KEM secret(s)`，还可能有多个 prekey、ratchet key、PSK  
↓ 新假设：至少一个输入秘密不可预测；长度与解析唯一；KDF 对部分受控输入仍是 PRF/提取器；删除时序正确  
↓ 问题：只拼接而不绑定公钥/密文；一个分量被固定、重放或跨会话复用；错误的 key erasure 使所谓 PQ forward secrecy 失效。[1][2]

### B. 单一密码假设 → 异构且随时间变化的假设

`CDH/EUF-CMA`  
↓ 变为 `CDH + Module-LWE + KEM IND-CCA + KDF/RO + signature + combiner`  
↓ 新假设：经典期、未来量子期、在线量子期分别由哪些分量承载保密与认证  
↓ 问题：论文只证明保密而部署声称“量子安全”；经典签名在 `Q-now` 下仍可被伪造；某分量失守后是否真的“平滑降级”取决于组合与 transcript。[3][5][6]

### C. 一个 KDF 输入 → hybrid KDF/combiner

`KDF(DH)`  
↓ 变为 `KDF(ss_c || ss_pq [, pk_c,pk_pq,ct_c,ct_pq,context])`  
↓ 新假设：split-key PRF、domain separation、唯一/无歧义编码、ciphertext binding；ROM/QROM 选择  
↓ 问题：简单 `H(ss_c || ss_pq)` 一般不足以给出主动攻击下的通用 IND-CCA；缺少 `ct/pk/context` 可产生 chosen-ciphertext、misbinding、跨协议或跨模式攻击。[2][3][4]

### D. DH 公共值 → 新 KEM ciphertext 与非对称贡献

`g^x, g^y`  
↓ 新增 `pk_pq, ct_pq, key-id`，且通常一方生成 KEM keypair，另一方 encapsulate  
↓ 新假设：pk、ct、共享秘密与双方身份/角色有唯一关系；发起方知道使用的是 one-time 还是 reusable key  
↓ 问题：KEM contribution misbinding、re-encapsulation、恶意目录替换、单向贡献、one-time/last-resort 混淆。[7]

### E. “解密失败” → implicit rejection 与丰富的 failure behavior

`DH` 通常无同类 decapsulation 分支  
↓ KEM `Decap(sk,ct)` 可能输出 `⊥`、伪随机键、不同错误码或不同时间  
↓ 新假设：无论合法性、密文长度和内部失败点，外部观察一致；调用方不能把失败键当成功键  
↓ 问题：padding/plaintext-checking oracle、密钥恢复、状态不同步、重试放大、DoS；源码“无分支”也可能被编译成变量时间指令。[18][19]

### F. 签名一个 transcript → transcript 体积和语义扩大

`Sig(identity, DH shares, nonces)`  
↓ 必须覆盖双方经典/PQ 公钥、密文、算法/版本、角色、会话 ID、KDF context、PSK 模式  
↓ 新假设：编码无歧义、角色与算法域分离、所有影响密钥的字段都被认证  
↓ 问题：公钥类型混淆、UKS、KEM secret 对错误身份、SSH/TLS 扩展降级、跨协议签名重用。[5][7][17]

### G. 固定套件 → 双栈协商和 fallback

`one protocol/version`  
↓ 客户端/服务端同时支持 classical、hybrid、PQC-only，兼容中间盒和旧节点  
↓ 新假设：最终选择是双方能力的经认证函数；fallback 原因和策略进入 transcript  
↓ 问题：删除 PQ 组、强制经典回退、版本/扩展截断、策略降级；固定-suite 证明对此保持沉默。[5][17]

### H. 一个协议状态 → 更多轮次、分片与 ratchet 状态

`one handshake state machine`  
↓ IKE_INTERMEDIATE 增加轮次；消息因 PQ 密钥/密文分片；消息协议加入稀疏 PQ ratchet  
↓ 新假设：轮次编号、分片重组、并发会话、prekey 消耗和删除原子一致  
↓ 问题：重放、状态分叉、key reuse、rollback、会话层与密码层边界错误。IKEv2 论文将 fragmentation 视为黑盒；PQ3 的 injective agreement 依赖额外会话处理假设。[8][9]

### I. 算法模型 → 实现/编译器/硬件

`ideal KEM/signature`  
↓ 大向量、多项式运算、压缩/解压、re-encryption check、复杂错误路径  
↓ 新假设：恒定时间、内存清除、输入验证、API type safety、正确随机数  
↓ 问题：Kyber/HQC 计时密钥恢复、故障诱导、错误码 oracle、密钥材料残留；这些通常不在 Tamarin/ProVerif 的原子等式理论内。[18][19]

## 1.2 一句话安全边界

> **Hybrid 的正确目标不是“两个算法都跑了”，而是：在明确的腐化与量子时间线下，每个影响会话密钥或 peer identity 的值都被唯一编码、域分离、认证并进入组合；一个分量失败时，剩余分量的保证不被接口、状态或跨模式调用绕过。**

---

# 第二部分：完整安全性质清单

下表中“攻击方式”是最小反例思路，不表示所有列举协议都存在该漏洞。

## 2.1 Confidentiality properties

| 性质 | 密码学定义 | 直观解释 | Hybrid PQC 中的重要性 | 典型攻击方式 |
|---|---|---|---|---|
| Secrecy | 对满足 freshness 条件的会话密钥/消息，攻击者不能计算该值 | 攻击者拿不到明文或键 | 最基础，但必须说明是经典、HNDL 还是在线量子攻击者 | 被动记录后破经典 DH；腐化 prekey；KDF 漏输入 |
| Indistinguishability | 攻击者不能区分真实密钥/密文与同分布随机量，优势可忽略 | 不仅“不知道”，连是否真实也判断不了 | 组合器通常以此证明“一个输入安全即可” | 通过失败、长度、时间或关联密文区分 |
| IND-CPA | 可选明文/encapsulation 观察下，挑战密文不泄漏挑战比特 | 被动/选择输入仍保密 | 对每会话全新临时 KEM key 的较弱但有时足够的目标；SSH 2025 证明说明协议层未必要求 IND-CCA。[6] | 重用静态 key 后加入 decap oracle 即超出模型 |
| IND-CCA | 除挑战密文外可查询 decapsulation，仍不能区分挑战键 | 主动篡改密文也学不到键 | 长期/可复用 KEM key 与 active network 常需此级别；但它不保证 pk/ct/secret 的关系绑定 | 修改 hybrid 密文的一半；利用未绑定 ciphertext；错误 oracle |
| Forward secrecy (FS) | 会话完成并删除临时秘密后，后来泄漏长期密钥不恢复旧会话键 | 今天丢身份私钥，昨天仍安全 | 必须分别问经典/PQ 分量的临时性和删除时刻 | `C-LT` 后解密旧静态 KEM ciphertext；使用 reusable prekey |
| Post-compromise security (PCS) | 某时刻状态泄漏后，经过包含新鲜未知熵的更新，未来会话重新安全 | 被攻陷后能“自愈” | Ratchet 中经典与 PQ 更新频率、乱序与丢包决定恢复窗口 | 持续阻断 PQ ratchet；重放旧 encapsulation；回滚状态 |
| Future secrecy | 本文按 secure messaging 用法：当前状态泄漏后，未来密钥在更新后恢复保密；不与 FS 混用 | 泄漏不永久污染未来 | PQXDH 的 prekey 污染和稀疏 ratchet 使恢复边界更复杂 | re-encapsulate 已知 secret 到未来 prekey；抑制新贡献 |
| Hybrid robustness | 在定义的攻击接口下，只要至少一个分量满足其假设，组合输出仍不可区分 | 一条腿断了仍站得住 | 是 hybrid 的核心价值，但需要强组合器和非共享失效模式 | 控制一个输入并利用 KDF/ct 未绑定影响另一个输入 |
| Graceful degradation | 对每种分量失守组合，协议保证恰好降至剩余分量的安全级别，而非灾难性全失守 | 失效后果可预测 | 防止年轻 PQC 或旧经典算法突然失守时连带击穿另一分量 | cross-mode oracle、shared-key use、类型混淆、共同侧信道 |

## 2.2 Authentication properties

| 性质 | 密码学定义 | 直观解释 | Hybrid PQC 中的重要性 | 典型攻击方式 |
|---|---|---|---|---|
| Entity authentication | 一方确信指定实体参与了相关运行 | 对面确实是 Bob | PQ 保密 KEX 若仍靠经典签名认证，在 `Q-now` 下不成立 | 伪造经典签名；替换目录中的 KEM key |
| Mutual authentication | 双方分别获得 entity authentication | Alice 与 Bob 双向确认 | KEM 往往天然单向；增加 PQ 分量不能自动补齐另一方向 | 恶意 serving network/HN masquerade；单边确认 |
| Key authentication | 一方确信除期望 peer 外无人能得到该会话键 | 只有我们两方知道键 | hybrid 输出必须同时绑定 peer 与每个分量 | UKS、malicious key registration、secret misbinding |
| Key confirmation | 一方获得证据：peer 实际算出了同一键 | 对方不只是“可能能算”，而是已经持有 | decap failure 或 KDF 分歧可让双方不同步；finished/MAC 必须覆盖正确 transcript | 删除 confirmation；让一方用 fallback 键 |
| Agreement | 若一方完成并声称参数 `d` 与 peer，则 peer 曾以相容角色运行且同意 `d` | 双方对关键事实一致 | `d` 应包含身份、套件、所有 pk/ct、会话 ID 与 key schedule context | 修改未签名算法字段或 key-id |
| Explicit agreement | agreement 加上 peer 已完成/明确确认（常以 matching completion 表达） | 双方都确认“握手完成且内容一致” | 防止 PQ ciphertext 失败但本地仍提交状态 | 截断最后一条 confirmation；不同 finished keys |
| Implicit agreement | 若对方完成则值会一致，但未必有其已完成的证据 | 参数一致性有保证，活性/完成未知 | 适合某些异步协议，但不能冒充 explicit auth | 延迟/丢弃最后消息；把推定完成当实际完成 |
| UKS resistance | 不存在双方得到同一键，却对 peer identity 认知不同的运行 | 同一把键不能“各认各的人” | 多个公钥与 key-id 增大 identity/key 错配面 | 替换身份、公钥或角色但保持 shared secret |
| Identity binding | 会话键和接受事件唯一绑定双方身份、角色、凭据及其 KEM/DH keys | 密钥明确属于谁、以什么角色建立 | PQXDH 的 key confusion/re-encapsulation 直接说明 IND-CCA 不够 | `K-repl`、签名类型混淆、目录服务器替换 |

## 2.3 Key-establishment properties

| 性质 | 密码学定义 | 直观解释 | Hybrid PQC 中的重要性 | 典型攻击方式 |
|---|---|---|---|---|
| Key freshness | 挑战会话未因规定的 Reveal/Corrupt 查询而失去资格，并含足够新鲜熵 | 这把键不是已经泄漏/陈旧的 | 必须为每个经典/PQ 分量和不同阶段分别定义 freshness | 重用 KEM keypair；过早腐化；随机数重复 |
| Key uniqueness | 不同逻辑会话除可忽略概率外不产生相同最终键 | 不同会话不撞键 | 重放/重封装同一 KEM secret 可污染多个会话 | 固定一分量、重放另一个；KDF 缺 session ID |
| Session-key independence | 泄漏一个会话键/分量秘密不帮助恢复或控制其他会话键 | 一次失守不扩散 | PQXDH re-encapsulation 展示跨 prekey 污染 | `C-PQ` 后把已知 secret 绑定到未来 pk |
| Key separation | 不同用途/阶段/方向的键在计算上独立并有唯一 label | 握手键不能当应用键或导出键 | hybrid key schedule 更长；标签碰撞会让证明依赖额外假设 | label/阶段遗漏；同一 HMAC 调用域重叠 |
| Key-compromise resilience | 在指定静态/临时/一方密钥腐化组合下，未授权会话仍安全；含 KCI 等 | 丢一类钥匙不应打开所有门 | 需要完整 compromise lattice，而非一句“一个分量安全” | `C-LT` 后冒充第三方给受害者；跨分量腐化 |
| Contributiveness | 每个应贡献的参与方/分量都能影响最终键，任何一方不能单独预定它 | 不能由一方完全选键 | KEM 非对称；one-pass/offline prekey 尤其需定义谁贡献什么 | 恶意 encapsulator 固定输出；抑制一分量 |
| KEM contribution binding | 接受的最终键与特定 KEM `(pk,ct,ss)`、拥有者、角色和会话唯一关联 | PQ 那一份贡献不能被搬到别的 key/session | `SH-CR`/key-binding 是 PQXDH 暴露的新增关系性质 | re-encapsulation、misbinding、duplicate key selection |

## 2.4 Protocol-integrity properties

| 性质 | 密码学定义 | 直观解释 | Hybrid PQC 中的重要性 | 典型攻击方式 |
|---|---|---|---|---|
| Transcript integrity | 双方完成时，对全部安全相关消息序列持相同且经认证的视图 | 握手历史不能被悄悄改写 | 新 pk/ct/扩展/分片必须进入签名、Finished 或 transcript hash | 删除 PQ 扩展；替换 ct；SSH prefix truncation |
| Context binding | 键绑定协议名、版本、套件、角色、身份、阶段与应用上下文 | 同一材料换个场景不能继续有效 | hybrid KDF 若只看 secrets，会产生 cross-context reuse | KDF `info` 为空；角色反射；exporter 混用 |
| Downgrade resistance | active attacker 不能使双方采用低于共同可用策略的安全级别而不被检测 | 不能被逼回 classical | 双栈迁移期的首要新增性质 | 删除 hybrid group/extension；伪造 fallback 条件 |
| Negotiation integrity | 双方对 offered/selected algorithms、参数和策略一致，且选择被认证 | 选了什么双方说法一致 | 固定套件 KEX 证明通常不覆盖此项 | 重排/裁剪算法列表；中间盒兼容回退 |
| Replay resistance | 旧消息不能导致新接受、重复副作用或旧键复用 | 老包不能变成新会话 | 大 prekey/ciphertext、离线接收和 ratchet 状态加重重放面 | 重放 ct/key-id；复用 sequence number |
| Cross-session security | 并发/顺序会话之间的消息、秘密和腐化不能非预期相互影响 | 一个会话不能寄生另一个 | 共享 static KEM key、缓存、prekey pool 会打破独立性 | session splicing、re-encapsulation、state clone |
| Cross-protocol security | 同一密钥/原语跨协议使用时，不能把一个协议的 oracle 当作另一个的攻击工具 | A 协议消息不能骗 B 协议处理 | 迁移期间 hybrid/standalone 与旧/新版本共存 | 无 domain tag；同 key 同时 decap standalone/hybrid |

## 2.5 PQC-specific properties

| 性质 | 密码学定义 | 直观解释 | Hybrid PQC 中的重要性 | 典型攻击方式 |
|---|---|---|---|---|
| Quantum-attacker resistance | 对量子多项式时间攻击者，在规定的经典/量子交互接口下优势可忽略 | 攻击者有量子计算机仍破不了 | 必须说明 `Q-now` 还是 `Q-later`，以及认证是否 PQ | HNDL；在线伪造经典签名；量子搜索放大 |
| QIND security | 允许量子挑战状态/量子查询的不可区分性族；具体定义依加密对象而异 | 连量子态/叠加查询也不泄漏挑战 | 对只传经典消息的 TLS/KEM，通常应写“post-quantum IND-CCA against QPT”，不能用模糊的 QIND 替代 | 叠加加密/解密查询区分；定义接口过弱 |
| QROM-related security | 攻击者可对理想 hash 作量子叠加查询时，归约仍成立 | hash oracle 也能量子访问 | 经典 ROM 证明不自动提升到 QROM；CryptoVerif 2024 明确不覆盖 QROM | 利用重编程/测量差异；把 ROM 证明误作 QROM |
| Quantum-safe composition | 各子证明与组合定理对同一量子接口、腐化时序和并发环境可组合 | PQ 安全部件拼起来仍 PQ 安全 | classical proof step、签名或 KDF 可能是薄弱环节 | 混用经典安全 PRF/签名；非 UC 组合 |
| Hybrid security | 任一指定分量安全时，整体在目标游戏中安全 | 经典与 PQ 至少保住一边 | 必须分别给经典分量/PQ 分量失守的两套归约 | combiner 未绑定 ct；共同实现失效；共享随机数 |
| Migration security | 双栈、升级、回退、密钥复用和策略变化全过程维持明示保证 | 过渡期也不出洞 | 最接近真实部署、目前证明覆盖最弱 | downgrade、cross-mode decap、证书/算法错配 |

## 2.6 Implementation-related properties

| 性质 | 密码学定义/工程判据 | 直观解释 | Hybrid PQC 中的重要性 | 典型攻击方式 |
|---|---|---|---|---|
| Side-channel resistance | 可观察时间/缓存/功耗/电磁/故障分布与秘密无可利用相关性 | 运行痕迹不泄钥 | PQ 解码、压缩、re-encryption check 路径复杂 | KyberSlash；HQC 除法计时；cache/power oracle |
| Decapsulation-failure handling | 所有失败对外一致，失败键不被接受，重试/日志不泄漏内部判定 | 失败不能成为 oracle | implicit rejection 的安全依赖精确实现与调用方 | 错误码/时延差；应用继续使用 failure key |
| Invalid-ciphertext robustness | 任意 malformed ct 不泄密、不崩溃、不造成跨状态差异 | 垃圾输入也安全 | active attacker 可廉价发送大量大密文 | chosen-ciphertext timing、parser differential、DoS |
| API-misuse resistance | 类型、角色、算法、key usage 与生命周期由接口强制或可审计 | 难以把对的原语用错 | hybrid/standalone 共存时最易传错 key/ct/label | 相同字节类型；跨模式同 key；忽略返回码 |
| State consistency | 持久化、并发、崩溃恢复、回滚后双方 key/epoch/prekey 消耗仍满足协议不变量 | 状态机不会分叉或复用旧材料 | ratchet、离线 prekey、IKE 多轮和分片都依赖状态 | rollback、双花 prekey、乱序导致重复 accept |

---

# 第三部分：Property–Attacker Capability Matrix

## 3.1 读表规则

- “能力”回答攻击者**获得什么**；“改变量/动作”回答攻击者**改变什么**。
- “证据”严格区分：`已攻击`、`形式工具找到反例`、`条件证明`、`尚属研究目标`。
- Tamarin/Squirrel 适配度：`高`＝主要是 trace/state/腐化关系；`中`＝可建模，但计算性质需抽象公理；`低`＝应由 CryptoVerif/EasyCrypt/Coq/代码验证或实测主导。

| Security property | Required attacker capability | 攻击者改变什么 / attack idea | 失败性质与 Hybrid 例子 | 已有论文证据 | Formal verification target / 适配度 |
|---|---|---|---|---|---|
| Secrecy under HNDL | `P + Q-later` | 记录握手，未来用 Shor 破解经典 DH | 旧会话密钥保密失败；classical-only TLS/SSH | 混合 TLS/SSH 的限定模型给出 PQ FS 条件证明。[5][6] | `Secret(k) & QuantumAfter(t)`；Tamarin 高，PQ-Squirrel/CryptoVerif 更适合计算健全性 |
| Online PQ authentication | `A + Q-now` | 量子破解/伪造仍为经典的签名认证，主动 MITM | entity/mutual auth；“PQ KEX + ECDSA cert” | CSF 2024 主要证明未来量子保密，并不把经典签名变成 PQ 认证。[5] | `Commit ⇒ Running` 且签名可在 Q 时刻被攻破；Tamarin 高 |
| IND-CPA | `P` 或无 decap oracle | 区分真实/随机 KEM key | 被动保密；ephemeral hybrid SSH KEX | S&P 2025 在整体 SSH ACCE/QROM 证明中表明 ephemeral KEM 可只需 IND-CPA。[6] | 计算游戏；Tamarin 低，Squirrel/CryptoVerif/Coq 高 |
| IND-CCA / ciphertext binding | `A + O-dec` | 修改 hybrid ciphertext 的一半，查询相关密文 | active confidentiality；naive hybrid KEM | CtKDF 在 ROM 下需把 ciphertext/public info 注入 `info`；generic simple hash 并非自动 CCA。[2][3] | CCA challenge + decap queries；Tamarin 低，CryptoVerif/EasyCrypt/Coq 高 |
| Hybrid robustness | 控制/破解一个分量 | 固定 `ss_c` 或 `ss_pq`，尝试使最终键可预测 | strongest-component security；X25519+ML-KEM | Campagna–Petcher、X-Wing、split-key PRF 给出不同模型下条件证明。[1][3][4] | 两套游戏：break classical / break PQ；符号工具中用二选一 reveal，适配中 |
| Graceful degradation | 一个分量全破 + `A` | 利用被破分量制造 oracle、类型混淆或共同失败 | 不应从“降至另一分量”变成“全失守” | X-Wing 给两方向归约，但仅对具体构造；跨模式 oracle 由扩展 hybrid-security 工作补充。[3][4] | compromise lattice；Tamarin 高（关系），计算强度由 CryptoVerif/Coq |
| Forward secrecy | `C-LT` 在完成后 | 用长期身份/静态 KEM key 解旧 ciphertext | Hybrid TLS/IKE/SSH 旧会话 secrecy | TLS/SSH、IKEv2 均有条件结果，但删除与腐化时序不同。[5][6][8] | `RevealLT@j & j>i ⇒ not K(k)`；Tamarin 高 |
| PQ forward secrecy | `P + C-LT + Q-later` | 记录后再破长期经典与 PQ 静态材料 | HNDL security；hybrid TLS/SSH/PQXDH | TLS/SSH 与 PQXDH 分别给出计算/符号结果，均有 freshness 限制。[5][6][7] | 时间点化 reveal；Tamarin/PQ-Squirrel 高 |
| Post-compromise security | `C-E/C-PQ/S-state` 后停止控制 | 阻断或替换恢复阶段的新鲜 PQ update | 未来消息仍可被读；PQ3/SPQR/Triple Ratchet | PQ3 证明细粒度 PCS；Triple Ratchet 给计算模型；SPQR 2026 将实现纳入分析。[9][14][15] | `Compromise@i & FreshUpdate@j ⇒ Secret after j`；Tamarin 高 |
| Session-key independence | `C-PQ + A + K-repl` | 把已知 KEM secret 重新封装/关联到另一 prekey | 一个 prekey 泄漏污染未来会话；PQXDH | ProVerif 找到 re-encapsulation trace；标准 IND-CCA 不排除，`SH-CR` 补足。[7] | `EqKey(s1,s2) ⇒ SameSession`；ProVerif/Tamarin 高 |
| Key uniqueness | `A` 或 RNG/状态控制 | 重放 `ct,key-id` 或复用 nonce，使不同 session 得同键 | cross-session collision/replay | PQXDH 反例与 PQ3 session-handling 条件显示其现实性。[7][9] | injective correspondence；Tamarin/ProVerif 高 |
| Key separation | `A + X-mode` | 让相同 KDF label/输入在握手、应用、exporter 或另一协议重合 | 不同用途键相关；hybrid TLS key schedule | CSF 2024 讨论 TLS draft 的 HMAC/Derive 域碰撞假设；标签修订消除额外假设。[5] | equationally distinct constructors/labels；Tamarin/Squirrel 高 |
| Contributiveness | 恶意一方或控制一个分量 | 选择/固定 encapsulation 输出，抑制另一方贡献 | 一方能预定会话键；one-pass KEM handshake | KEMTLS/AKEM 文献通过 AKE 游戏约束，但一般协议仍需单独定义。[11][13] | `Accept ⇒ FreshFrom(A) ∧ FreshFrom(B)`；Tamarin 中 |
| KEM contribution binding | `C-PQ + K-repl + A` | 保持 `ss`，改变 `pk/ct/key-id/owner` | agreement、identity binding、session independence；PQXDH | 已有正式攻击与 `SH-CR` 定义；Kyber 被证明满足所需性质，McEliece 不满足该形式。[7] | `Commit(pk,ct,ss,peer) ⇒ unique Running(...)`；ProVerif 高，计算证明需 CryptoVerif |
| Entity authentication | `A + K-repl` 或签名伪造 | 替换 prekey bundle/证书 key，完成冒充 | peer authentication；KEMTLS/PQXDH | KEMTLS 给 KEM-based server auth 模型；PQXDH 给 correspondence 与计算证明。[7][11] | `Commit(A,B) ⇒ Running(B,A)`；高 |
| Mutual authentication | `M-server + A` | 服务网络或 home network 伪装；仅一侧被认证 | DMRN/6G 主认证中的 UE–SN–HN agreement | 2024 DMRN 的 SVO/ProVerif 分析报告 HN masquerade 与不完整 mutual auth。[20] | 三方 agreement/correspondence；ProVerif/Tamarin 高 |
| Key authentication | `A + K-repl` | 让 Alice 与 Mallory/Bob 共享同一最终键但归属错误 | only-intended-peer-knows；hybrid prekey | PQXDH 的 binding 修复直接服务于此；普通 KEM IND-CCA 不足。[7] | secrecy + peer-param agreement；高 |
| Key confirmation | `A` | 删除/替换 Finished 或诱导 decap 分歧后单边提交 | explicit agreement/state consistency；TLS/IKE | TLS/SSH 证明包含相应认证阶段；IKE Tamarin 检查状态机。[5][8] | `CommitA(k) ⇒ CommitB(k)`；高 |
| Unknown-key-share resistance | `A + K-repl` | 保持 key 不变但换 identity/role/credential | 双方 peer 认知不同；hybrid KEM handshake | PQXDH public-key confusion/re-encapsulation 是具体近邻案例。[7] | 参数化 agreement lemma；高 |
| Identity binding | `A + K-repl + X-mode` | 交换 KEM/X25519 签名或将 key 放到错误算法槽 | post-quantum secrecy与认证同时失败；早期 PQXDH | ProVerif 找到 public-key confusion；实际 Signal 的长度/前缀降低可利用性，但 spec 被修订。[7] | `Accept(peer,alg,pk)` correspondence；ProVerif/Tamarin 高 |
| Transcript integrity | `A` | 修改未被签名/MAC/hash 覆盖的 `pk,ct,alg,role` | agreement/密钥认证；TLS/SSH/IKE | CSF 2024 的固定-suite proofs要求正确 transcript；Terrapin展示 SSH 可选消息脱离认证的后果。[5][17] | transcript equality at commit；Tamarin/Squirrel 高 |
| Context binding | `A + X-mode` | 去掉 KDF `info`、协议名或角色标签，跨协议重放输入 | cross-protocol/role-mixup；PQXDH/TLS | PQXDH 初始 ProVerif抽象遗漏 `info` 时出现 cross-protocol traces；实际字段阻断。[7] | typed/domain-separated constructors；高 |
| Negotiation integrity | `N-neg + A` | 裁剪 offered groups、改 selected group/扩展顺序 | 双方套件视图不一致 | CSF 2024 TLS 模型显式排除 negotiation；不能据固定套件证明宣称已解决。[5] | `Offer(A,L) & Select(B,x) ⇒ x∈L∩Policy`；Tamarin高，当前证据 GAP |
| Downgrade resistance | `N-neg + A` | 删除 PQ group 或强制 classical fallback | migration security/HNDL 失败；TLS/SSH 双栈 | Terrapin 实证破坏 SSH extension negotiation；虽非专攻 PQ KEX，却直接适用于迁移面。[17] | downgrade trace + policy facts；Tamarin高 |
| Replay resistance | `A` | 重放 KEM ct、prekey id、ratchet update 或可选握手消息 | injective agreement、freshness、state safety | PQ3 只有加入 session-handling 假设才证明 injective agreement；DMRN MAC 可重放。[9][20] | injective correspondence + consumed state；Tamarin高 |
| Cross-session security | `MU + A + C-PQ` | session splice、复用 keypair、secret re-binding | session independence/agreement | PQXDH re-encapsulation 已证；多用户具体界仍不足。[7] | unbounded sessions + adaptive corrupt；Tamarin高，具体界工具中 |
| Cross-protocol security | `X-mode + O-dec` | 同一 component key 既给 standalone decap 又给 hybrid decap | extended hybrid IND-CCA/migration security | Millerjord–Stebila–Steckel 2026 专门扩展模型，允许访问组合及分量 decap 接口。[4] | 多 oracle 游戏；Tamarin中、Coq/EasyCrypt/CryptoVerif高 |
| QROM security | 量子叠加 hash 查询 | 利用经典 ROM 证明不覆盖的 oracle 行为 | PQ indistinguishability；hybrid combiner/SSH | SSH S&P 2025 给 QROM 分析；CSF CryptoVerif 明确不覆盖 QROM。[5][6] | PQ-Squirrel/专用 QROM proof；Tamarin低 |
| Multi-user security | `MU` + adaptive corruption | 在海量 pk/session 中选择弱目标、放大具体优势 | fleet-scale TLS/5G/MLS | 主流协议论文多以会话模型处理并发，但 KEM 多目标具体安全与跨用户 key registration 仍未闭环 | 多用户 game + concrete loss；Tamarin中、EasyCrypt/Coq高 |
| Side-channel resistance | `S-ch + O-dec` | 选择密文并测时间/除法延迟 | KEM sk recovery；Kyber/HQC component | KyberSlash 与 Divide and Surrender 均给出可执行密钥恢复。[18][19] | symbolic tools低；ct-verif/Jasmin/F*/实测高 |
| Decapsulation failure handling | `A + O-dec` | 比较合法/非法密文的错误、输出、重试或耗时 | IND-CCA 实现假设、state consistency | KyberSlash将差异放大为 plaintext-checking oracle；隐式拒绝仍需调用方正确处理。[18] | 错误等价/observational equivalence；ProVerif中、代码/侧信道工具高 |
| Invalid-ciphertext robustness | `A` | 畸形长度/系数触发 parser、不同路径或资源消耗 | availability/confidentiality | HQC/Kyber案例证明“参考源码看似常数时间”仍不足。[18][19] | biprocess equivalence + fuzz/constant-time tests；符号中低 |
| API-misuse resistance | `X-mode` 或开发者失误 | 把 X25519 key 当 KEM key、复用 key usage、忽略 failure | identity binding、graceful degradation | PQXDH public-key confusion 在实现中恰由长度与算法前缀偶然挡住，说明应把类型约束变成规范不变量。[7] | typed model + executable refinement；F*/DY*/ProVerif高 |
| State consistency | `S-state + A` | 回滚 ratchet、重复消费 prekey、崩溃后恢复旧 epoch | PCS、replay、injective agreement | PQ3明确把会话处理留在模型外；SPQR 2026向实现级验证推进。[9][15] | mutable state/locks/rollback facts；Tamarin高，代码验证必要 |

## 3.2 矩阵给出的三条结论

1. **Tamarin/ProVerif 最适合“谁在何时知道/同意了什么”**：身份绑定、协商、重放、腐化时序、状态消耗。
2. **Squirrel/CryptoVerif/EasyCrypt/Coq 最适合“不可区分性为何从假设推出”**：IND-CPA/CCA、QPT/QROM、split-key PRF、具体 reduction loss。
3. **任何单一工具都不足以闭环实现风险**：constant-time、编译器、错误通道与持久状态需要代码级验证、差分测试和实测；理想路线是把同一安全事件与 key lifecycle 跨工具对齐。

---

# 第四部分：已有攻击、反例与迁移设计错误

## Case 1 — PQXDH public-key confusion（规范级、形式工具发现）

```yaml
Protocol: 早期 PQXDH 规范
Attacker capability: A + K-repl；可替换 prekey bundle 中的签名/公钥字段
Attack trace:
  1: Bob 分别发布 X25519 signed prekey 与 KEM signed prekey
  2: 两类签名消息未作足够算法域分离
  3: Mallory 交换签名及相应字段，使 KEM 操作落到 curve key、DH 操作落到 KEM key
  4: 在抽象规范中，攻击者据此计算所有组合输入并恢复最终密钥
Violated property: identity binding, entity authentication, post-quantum secrecy, context binding
Root cause: 相同签名域承载不同算法类型；规范没有把 key type/algorithm/role 绑定进签名
Deployment status: Signal 实现中的密钥长度不匹配和算法前缀阻止了论文中的直接利用；规范随后强化。因此这是“规范真实缺陷”，不是已知线上失陷
Possible formal model: ProVerif typed/untyped key constructors + correspondence；Tamarin 可表达 key-slot 交换
Reference paper: Bhargavan et al., Formal Verification of the PQXDH..., USENIX Security 2024 [7]
```

**研究含义**：实现中的“偶然防护”不应替代协议不变量。算法标识、key usage、角色和身份应该同时进入签名与 KDF context，并在 API 类型层强制。

## Case 2 — PQXDH KEM re-encapsulation / secret misbinding（规范级、计算性质缺口）

```yaml
Protocol: PQXDH prekey handshake
Attacker capability: C-PQ + A + K-repl；先得到一个 PQ prekey 私钥或其 decapsulated secret
Attack trace:
  1: 从已腐化的 PQ prekey 解出共享秘密 ss
  2: 构造另一对 (pk', ct')，使其 decapsulation 仍给出 ss
  3: 替换未来握手使用的 PQ public key、ciphertext 或 key-id
  4: 受害者接受，却把已知 ss 归因于不同 prekey/session
Violated property: session-key independence, KEM contribution binding, mutual agreement on PQ key, future secrecy
Root cause: 标准 IND-CCA 只隐藏 challenge key，不保证“已知某 sk 时 ss 唯一绑定 pk/ct”；KDF 又未显式包含全部 public keys
Deployment status: 论文证明 Kyber 具有额外 SH-CR 性质，实际所用构造可阻断；McEliece 型实例不满足论文给出的该性质，BIKE/HQC 当时未定
Possible formal model: ProVerif 查找跨 session same-secret trace；CryptoVerif/手工 reduction 证明 SH-CR
Reference paper: Bhargavan et al., USENIX Security 2024 [7]
```

**研究含义**：这是最强的反例之一——“KEM IND-CCA + 安全 KDF”仍不自动给出协议所需的公钥/密文/贡献绑定。

## Case 3 — PQXDH one-time 与 last-resort KEM key 不可区分（设计保证弱化）

```yaml
Protocol: PQXDH asynchronous prekey distribution
Attacker capability: P；或 M-server 选择不提供 one-time key
Attack trace:
  1: 发起者收到格式相同的 PQ signed prekey
  2: 发起者无法从被认证数据判断它是 one-time key 还是可复用 last-resort key
  3: 因而无法判断接收方是否会在首次使用后立即删除 decapsulation key
Violated property: 可审计的 PQ forward secrecy / key freshness guarantee
Root cause: key lifetime 与 usage class 未进入认证上下文；删除语义只存在于服务端状态
Deployment status: 论文将其定性为较弱保证/潜在问题，而非密钥恢复攻击
Possible formal model: Tamarin persistent/linear facts区分 OPK 与 reusable key；agreement 参数加入 key_class
Reference paper: Bhargavan et al., USENIX Security 2024 [7]
```

## Case 4 — PQ3 replay / injective agreement 依赖未建模 session layer（形式验证暴露的边界）

```yaml
Protocol: Apple iMessage PQ3
Attacker capability: A + S-state；重放、乱序或利用并发会话处理差异
Attack trace:
  1: 重放先前合法的 ratchet/会话消息
  2: 密码 ratchet 模型本身不能唯一排除第二次对应 accept
  3: 加入“会话层只交付/接受一次”等额外假设后，injective agreement 才可证明
Violated property: replay resistance, injective agreement, state consistency（若外层假设不成立）
Root cause: 安全责任跨越密码 ratchet 与未公开/未建模的 session-handling layer
Deployment status: 论文没有宣称实际 iMessage 可被该 trace 攻破；结论是证明依赖必须由外层实现满足
Possible formal model: Tamarin linear receive tokens、message IDs、state monotonicity；进一步连接源码/持久化模型
Reference paper: Linker, Sasse, Basin, A Formal Analysis of Apple's iMessage PQ3 Protocol, USENIX Security 2025 [9]
```

## Case 5 — DMRN 6G authentication 的 MAC replay / HN masquerade（形式分析报告漏洞）

```yaml
Protocol: DMRN，面向 5G/6G 的 PQC+PFS 主认证设计
Attacker capability: A；并考虑恶意/受损 serving network
Attack trace:
  1: 捕获 core/home network 产生的 MAC
  2: 因 MAC 验证未充分关联 freshness/sequence，重放旧 MAC
  3: 攻击者伪装网络实体；UE 对 serving network 的认证关系也不完整
Violated property: mutual authentication, freshness, replay resistance, entity/role binding
Root cause: 把 PQC key establishment 加入旧 AKA 流程，却没有同步补齐三方身份、序列和 MAC 上下文
Deployment status: ProVerif/SVO 模型中的反例；论文发表于 Applied Sciences，证据层级低于顶会案例，应独立复核模型
Possible formal model: ProVerif correspondence + nonce/sequence；Tamarin 更适合状态化 SQN、重同步和腐化 SN
Reference paper: You et al., Mitigating Security Vulnerabilities in 6G Networks..., Applied Sciences 2024 [20]
```

## Case 6 — SSH Terrapin extension negotiation downgrade（真实攻击，迁移邻接）

```yaml
Protocol: SSH Binary Packet Protocol / extension negotiation
Attacker capability: A；on-path 修改握手前后可选消息并操纵 sequence numbers
Attack trace:
  1: 在加密启用前注入或删除 SSH 消息，改变双方 sequence number
  2: 在不触发完整性失败的情况下截去加密信道起始消息
  3: 删除 EXT_INFO 等扩展协商，降级认证算法或关闭缓解措施
Violated property: transcript integrity, negotiation integrity, downgrade resistance
Root cause: 可选消息未完整绑定到已认证 transcript，且切换到加密时 sequence number 未重置/绑定
Deployment status: 对多种 SSH 实现可执行；不是对 ML-KEM 的密码分析，但直接证明“迁移扩展在固定-suite KEX证明之外”可以被降级
Possible formal model: Tamarin 有序消息 + sequence counter + channel phase；Squirrel 可研究 transcript observational equivalence
Reference paper: Bäumer, Brinkmann, Schwenk, Terrapin Attack..., USENIX Security 2024 [17]
```

## Case 7 — KyberSlash（实现级 chosen-ciphertext timing）

```yaml
Protocol: 使用 Kyber/ML-KEM decapsulation 的任意部署，包括 hybrid TLS/SSH/Signal 的 PQ 分量
Attacker capability: O-dec + S-ch；可提交选择密文并测量本地或某些远程时间
Attack trace:
  1: 构造让秘密相关除法输入落入可区分时间区间的 ciphertext
  2: 将时间差转成 plaintext-checking oracle
  3: 自适应恢复 Kyber secret key；论文在 Cortex-A7/M4 等平台给出攻击
Violated property: side-channel resistance, KEM secret confidentiality, decapsulation robustness
Root cause: 秘密相关整数除法；某些编译器/平台把源码运算实现为变量时间指令
Hybrid consequence: PQ 分量先失守；若 combiner 真正 robust，当前会话仍可降级到经典安全，但 HNDL 保证随未来量子攻击而消失。若组合/绑定有缺陷，后果可能更大
Possible formal model: 不适合纯 Tamarin；需 constant-time 类型/验证、编译后二进制分析和统计测试，再把 Leak(sk_pq) 事件反馈到协议模型
Reference paper: Bernstein et al., KyberSlash..., TCHES 2025 [18]
```

## Case 8 — Divide and Surrender（HQC 编译器生成除法计时）

```yaml
Protocol: HQC decapsulation 实现；可作为 hybrid KEM 的 PQ 分量
Attacker capability: S-ch + O-dec；共置 SMT 攻击者测量变量时间除法
Attack trace:
  1: 选择 ciphertext 并与受害者 decapsulation 共核运行
  2: 约百条 trace 构造高准确率 plaintext-checking oracle
  3: 论文演示两分钟内密钥恢复
Violated property: side-channel resistance, invalid-ciphertext robustness, graceful degradation assumptions
Root cause: 参考 C 代码的算术被编译器降低为 operand-dependent variable-time division
Possible formal model: 二进制 constant-time 分析 + protocol-level component compromise；纯符号模型只能把结果抽象为 reveal
Reference paper: Schröder, Gast, Guo, Divide and Surrender..., USENIX Security 2024 [19]
```

## Case 9 — Naive parallel KEM combiner 的 CCA 反例（构造级）

```yaml
Protocol: 将两个 KEM 输出简单送入 H/KDF 的通用 hybrid KEM
Attacker capability: A + O-dec；可改一部分 ciphertext 并查询相关 decapsulation
Attack trace:
  1: 保留 challenge ciphertext 的一个分量
  2: 替换另一分量，形成不等于完整 challenge 的新 ciphertext
  3: 查询 combined decapsulation；若 KDF 未绑定全部 ciphertext/public context，可保留或测试 challenge secret 的关联
Violated property: IND-CCA, ciphertext binding, hybrid robustness under active attack
Root cause: 把“至少一个 secret 随机”误当成主动安全；没有把完整 ct/pk/nonce 作为唯一 combiner context
Deployment status: 通用构造反例；CtKDF、X-Wing、split-key PRF 等给出在各自假设下的修复/证明
Possible formal model: EasyCrypt/Coq/CryptoVerif 游戏；ProVerif 可演示关系型 trace，但不能替代概率归约
Reference paper: Petcher–Campagna 2023; Barbosa et al. 2024; Millerjord et al. 2026 [2][3][4]
```

## Case 10 — Hybrid/standalone 共用 component key 的 oracle 穿透（新安全模型暴露）

```yaml
Protocol: crypto-agile API、S/MIME 或同时提供 standalone 与 hybrid KEM 的系统
Attacker capability: X-mode + O-dec；能访问 combined decap 与各 component decap 接口
Attack trace:
  1: 让同一长期 component key 同时注册到 standalone 和 hybrid 模式
  2: 把 hybrid ciphertext 的分量送到 standalone oracle，或反向处理
  3: 利用不同后处理/标签得到关联信息，绕过只允许 combined-oracle 的传统 IND-CCA模型
Violated property: cross-protocol security, migration security, extended hybrid IND-CCA
Root cause: 原安全游戏假设 component keys 与 combiner keys 独立；真实 crypto-agility 可能复用材料
Deployment status: 2026 工作提出扩展安全模型与 split-key PRF/post-processing 构造；是模型缺口与预防性设计，不是已知大规模部署攻击
Possible formal model: 多 oracle computational game；Tamarin可表达调用拓扑，但概率不可区分性需 Coq/EasyCrypt/CryptoVerif
Reference paper: Millerjord, Stebila, Steckel, IACR Communications in Cryptology 2026 [4]
```

---

# 第五部分：已解决问题、研究空白与选题地图

## 5.1 协议/方向覆盖图

| 方向 | 2020–2026 已有高质量证据 | 已覆盖 | 明确未覆盖/薄弱处 |
|---|---|---|---|
| Hybrid KEM combiner | Campagna–Petcher；CtKDF；X-Wing；Spilling-Cascade；extended hybrid security [1][2][3][4][22] | IND-CPA/CCA 条件、concrete combiner、部分机器证明、cross-mode oracle 新模型 | QROM 通用组合、key-binding 标准化、multi-user concrete bounds、故障/侧信道组合 |
| NIST PQC migration 相关构造 | ML-KEM 被用于 X-Wing、TLS/SSH、Signal ratchet 与 5G 设计的学术分析 [3][5][6][7][14][21] | 从候选 Kyber 到 ML-KEM 的 hybrid 构造论证；固定套件的 protocol proof | 标准版本/参数更新与证明、证书/签名迁移、双栈策略、fallback、同 key 跨模式 API；合规迁移文档不能替代这些密码学性质 |
| TLS 1.3 + PQC | KEMTLS CCS 2020；PQ-sound CryptoVerif CSF 2024 [5][11][12] | multi-stage KEM auth；固定 hybrid suite 的认证、FS、PQ FS | 协商/降级、tickets/resumption、post-handshake auth、完整 PKI/证书迁移、实现 |
| SSH hybrid | CryptoVerif CSF 2024；整体 SSH PQ ACCE/QROM S&P 2025 [5][6] | 固定 KEX、unilateral auth、FS/PQ FS；整体 secure-channel 模型 | 双栈 negotiation 与扩展完整性；cross-mode keys；全实现/状态；Terrapin 类迁移攻击 |
| IKEv2 + PQC | ACSAC 2021 Tamarin [8] | Minimal IKEv2 核心状态机、单个 IKE_INTERMEDIATE、secrecy/identity protection | 多 intermediate exchanges、fragmentation、EAP/cert/full auth、PQ signatures、实现 |
| Signal PQXDH | USENIX Security 2024 [7] | ProVerif + CryptoVerif；发现并修复 key confusion/re-encapsulation；SH-CR | 目录/多设备/备份、完整 ratchet、跨协议密钥复用、side channels |
| PQ ratchets | PQ3 USENIX 2025；Triple Ratchet EUROCRYPT 2025；SPQR CCS 2026 accepted [9][14][15] | 细粒度 FS/PCS/HNDL；带宽效率；SPQR 源码到模型的推进 | 会话/持久层、设备克隆/回滚、群组、metadata/deniability、量子网络模型 |
| Deniable PQ messaging | PKC 2022；Shadowfax USENIX 2026 [13][16] | 说明 KEM 替换会损失 deniability；给出 hybrid AKEM 方案 | 与真实 Signal ratchet/目录/多设备的完整组合与形式验证 |
| MLS PQC | 截止日有 hybrid ciphersuite/实现方向，但本调研未定位到与 PQXDH/PQ3 同等的、peer-reviewed 端到端 hybrid MLS 形式证明 | 构件与 TreeKEM/MLS 的经典基础可复用 | 群组成员变更、epoch、external join、proposal/commit binding、downgrade、PCS 的 PQ/hybrid 联合模型 |
| 5G/6G authentication | DMRN ProVerif/SVO 2024；5G-AKA-HPQC 2026 等 [20][21] | 初步 mutual auth/secrecy/PFS 查询、三方架构 | 模型质量参差；完整 3GPP 状态、SQN resync、roaming、serving-network compromise、multi-user/side-channel |
| Implementation | KyberSlash TCHES 2025；HQC USENIX 2024 [18][19] | 真实 secret-dependent timing 与 key recovery | 将 constant-time/编译器证据组合进协议级 graceful-degradation/PCS 定理 |

> **关于 MLS 的负面结论是“本次学术检索未找到同等级证据”，不是对不存在任何工作的绝对证明。** 该方向应先做系统 snowballing，再把标准草案与实现 commit 固定为可复现实验对象。

## 5.2 八个重点问题的状态判定

### 1. Hybrid KEM composition — 基础已解决，真实接口仍开放

**已解决**：parallel/cascade/concatenation combiners 在明确 ROM/标准模型、IND-CPA/CCA 或 split-key PRF 假设下已有归约，X-Wing 给出具体 X25519+ML-KEM-768 的双方向安全证明；Spilling-Cascade改善带宽。[1][2][3][22]

**仍开放**：

- `pk/ct/ss` binding 是否应成为通用 KEM/combiner API 性质，而非协议临时补丁；
- 同一 key 在 hybrid/standalone、多协议、多算法版本中复用的 composable 定理；
- classical ROM 到 QROM 的通用提升；
- decapsulation failure、multi-user loss 和侧信道作为组合器输入，而非事后 `Reveal`。

### 2. Identity binding — 已有关键反例，缺少统一定义

**已解决**：PQXDH 证明 key type/domain separation 与 KEM `SH-CR` 必要；把全部 public keys 加入 KDF 是直接强化。[7]

**仍开放**：跨 TLS cert、SSH host key、Signal directory、MLS credential 的统一 `identity–role–algorithm–key–ciphertext` binding 定义；恶意 key registration、duplicate keys、多设备身份和证书更新的组合证明。

### 3. Classical/PQC compromise interaction — 只有局部格子，缺完整 lattice

**已解决**：代表性论文分别研究了“经典分量失守”“PQ 分量失守”“长期 key 后泄漏”“未来量子出现”。[3][5][6][7][9]

**仍开放**：多阶段协议需要系统枚举 `(C-LT, C-E, C-PQ, session-key reveal, state clone, Q time)` 的偏序与恢复点；尤其是一分量的实现泄漏是否可通过错误/API/状态影响另一分量。

### 4. Transcript binding — 固定套件清楚，迁移 transcript 不清楚

**已解决**：TLS/SSH 固定 hybrid KEX 中，公共值、KEM ct 和 transcript hash 的认证作用已有证明；PQXDH 也验证 `info`/public-key binding。[5][7]

**仍开放**：offered list、selected suite、fallback reason、middlebox retry、resumption、0-RTT、post-handshake auth、分片重组是否全部被同一个 transcript invariant 覆盖。Terrapin说明“扩展在信道边界外”会真实降级。[17]

### 5. Formal verification gap — 工具已 PQ 化，但覆盖层仍断裂

**已解决**：PQ-Squirrel 给出交互式 computational PQ proof；CryptoVerif 2024 给黑盒交互量子攻击者健全性；Tamarin/ProVerif 已处理 IKE、PQXDH、PQ3 的无界 trace/state。[5][7][8][9][10]

**仍开放**：

- 同一规范在 Tamarin（状态/攻击 trace）与 CryptoVerif/Squirrel（概率/量子）间共享事件语义；
- 从协议模型到 verified parser/KDF API/持久状态的 refinement；
- 证明的“未覆盖项清单”机器可读并随代码/标准版本更新；
- 大消息分片、并发、崩溃恢复和多设备状态的可扩展验证。

### 6. Quantum attacker modeling — HNDL 可表达，QROM/在线量子不统一

**已解决**：符号模型可以用时间化规则让经典原语在量子事件后可破；PQ-Squirrel/CryptoVerif 支持相应计算论证；SSH 2025 进入 QROM。[5][6][8][10]

**仍开放**：量子随机预言机、量子网络输入、量子状态与经典协议状态混合，以及 `Q-now` 的 PQ authentication/deniability/composition。不要用“将 DH 标为可破”冒充 QROM 证明。

### 7. Multi-user security — 协议并发有模型，具体大规模风险不足

**已解决**：ProVerif/Tamarin 通常允许无界 sessions；AKE 模型也可表达多参与者与 corrupt queries。

**仍开放**：百万用户/多目标安全损失、prekey pool、相同算法不同租户、批量 decap、恶意注册和自适应目标选择；5G/MLS 是最自然试验场。

### 8. Implementation vs symbolic model gap — 已有强攻击，尚未组合

**已解决**：KyberSlash/HQC 清楚证明编译后 timing 可以恢复 KEM key；SPQR 2026 把 F* runtime safety、手写 ProVerif 与源码分析放入同一 artifact，是积极方向。[15][18][19]

**仍开放**：binary-level constant-time 证书如何成为协议定理前提；failure key、错误码、重试、内存清除、rollback 如何映射到 Tamarin/ProVerif 事件；以及“一个分量侧信道失守后”的定量 graceful degradation。

## 5.3 推荐博士/研究课题（按新颖性 × 可验证性排序）

### Topic A — Full-stack hybrid migration theorem for TLS/SSH

**问题**：把固定-suite KEX 证明扩展到 offer/select/fallback/resumption/0-RTT/host-key or certificate migration。  
**攻击者**：`N-neg + X-mode + C-LT + Q-later`。  
**性质**：negotiation integrity、downgrade resistance、cross-protocol、PQ FS。  
**方法**：Tamarin 建全状态与降级 trace；CryptoVerif/PQ-Squirrel证明选定套件的计算安全；以 Terrapin 型 trace 作回归。  
**可交付**：一套“证明覆盖 manifest”，明确标准字段、实现版本、模型 lemma 的对应关系。

### Topic B — Unified KEM contribution and identity-binding framework

**问题**：统一 `SH-CR`、key commitment/misbinding、malicious registration、duplicate keys 与 hybrid AKE agreement。  
**攻击者**：`K-repl + C-PQ + O-dec + MU`。  
**性质**：identity binding、session independence、UKS、KEM contribution binding。  
**方法**：先给 computational game，再在 ProVerif/Tamarin 中给可自动检查的 correspondence abstraction；对 ML-KEM、HQC、code-based KEM 和 X-Wing实例化。

### Topic C — Extended hybrid security under crypto-agile APIs

**问题**：同一 component key 在 standalone/hybrid、TLS/SSH/S/MIME、多版本 API 间复用。  
**攻击者**：`X-mode + O-dec + adaptive corrupt`。  
**性质**：cross-protocol、migration security、graceful degradation。  
**方法**：扩展 2026 split-key PRF 模型，增加 key usage policy、错误与并发；EasyCrypt/Coq机器证明，生成 misuse-resistant API。

### Topic D — Compromise lattice and recovery semantics for hybrid ratchets

**问题**：经典 DH ratchet、PQ sparse ratchet、身份 key、备份/多设备状态在不同时间被泄漏时，精确何时恢复。  
**攻击者**：`C-E/C-PQ/C-LT/S-state/Q-later` 任意组合。  
**性质**：FS、PCS、future secrecy、session independence。  
**方法**：以 PQ3/Triple Ratchet/SPQR 为基线，在 Tamarin 建时间偏序，在 PQ-Squirrel/手工游戏验证关键恢复步；纳入乱序/丢包/设备克隆。

### Topic E — Hybrid MLS end-to-end formal verification

**问题**：把 hybrid KEM/HPKE 扩展至 group epoch、proposal/commit、external join、成员移除和 PCS。  
**攻击者**：`M-server + MU + S-state + N-neg + adaptive group corruption`。  
**性质**：group agreement、epoch authenticity、PCS、downgrade、cross-session。  
**方法**：Tamarin/ProVerif 做状态与成员关系，CryptoVerif/PQ-Squirrel承接 hybrid HPKE/KEM 假设；验证真实 OpenMLS 风格实现。  
**新颖性依据**：本调研未找到与 PQXDH/PQ3 同等级的 peer-reviewed 完整 hybrid MLS 证明。

### Topic F — Compiler-aware decapsulation failure refinement

**问题**：把 constant-time binary evidence、implicit rejection、API result handling接到协议安全证明。  
**攻击者**：`S-ch + O-dec + fault`。  
**性质**：side-channel resistance、invalid-ct robustness、graceful degradation。  
**方法**：Jasmin/F*/binary analysis 产生 `NoLeak` 或显式 `Leak(bit)` 合约；自动导入 Tamarin/CryptoVerif；以 KyberSlash/HQC 攻击作为负测试。

### Topic G — Full 5G/6G hybrid AKA with serving-network compromise

**问题**：在真实 SQN/resynchronization、roaming、HN/SN/UE 三方信任和多用户环境中验证 PQ migration。  
**攻击者**：`M-server + A + C-LT + MU + Q-later`。  
**性质**：mutual auth、subscriber identity privacy、PFS、KCI、replay、role binding。  
**方法**：Tamarin 状态模型优先；对现有 DMRN/5G-AKA-HPQC ProVerif claims 作独立重现和模型差异审计。

### Topic H — PQ deniability as a migration property

**问题**：在 hybrid handshake + ratchet + multi-device 中，同时保持 strongest-component confidentiality/authentication 与 honest/dishonest-receiver deniability。  
**攻击者**：接收者腐化、未来量子攻击、transcript coercion。  
**性质**：deniability、hybrid security、PCS、identity binding。  
**方法**：以 PKC 2022 与 Shadowfax 2026 为 primitive/AKEM 基线，接入 Signal 状态机并进行 computational + symbolic 双重验证。[13][16]

## 5.4 总结路径

```text
Existing research
  ├─ combiner reductions: CtKDF / X-Wing / split-key PRF
  ├─ protocol proofs: hybrid TLS / SSH / IKEv2 / PQXDH / PQ3
  ├─ emerging code proofs: SPQR
  └─ implementation attacks: KyberSlash / HQC timing
        ↓
Known solved problems (within explicit models)
  ├─ strongest-component key indistinguishability for several constructions
  ├─ fixed-suite hybrid TLS/SSH secrecy, authentication and PQ-FS variants
  ├─ minimal IKE_INTERMEDIATE core properties
  ├─ PQXDH key-confusion/re-encapsulation diagnosis and repair conditions
  └─ PQ3/Triple Ratchet 的若干 FS/PCS/HNDL 定理
        ↓
Open problems
  ├─ negotiation/fallback/resumption and full migration transcript
  ├─ identity/KEM-contribution binding across registrations and protocols
  ├─ full compromise lattice, multi-user and cross-mode key reuse
  ├─ hybrid MLS and full 5G/6G state machines
  ├─ QROM/online quantum/composable quantum modeling
  └─ compiler/side-channel/state persistence → protocol theorem refinement
        ↓
Potential PhD/research topics
  ├─ Full-stack TLS/SSH migration verification
  ├─ Unified KEM binding security
  ├─ Crypto-agile extended hybrid security
  ├─ Hybrid ratchet compromise lattice
  ├─ Hybrid MLS verification
  └─ Compiler-aware decapsulation + protocol composition
```

---

# 第六部分：关键文献证据账本

以下每条都给出“题名—年份—venue—主要贡献—讨论的准确安全问题”。编号与正文引用一致。

1. **Matthew Campagna, Adam Petcher, “Security of Hybrid Key Encapsulation,” 2020, IACR ePrint 2020/1364.** 主要贡献：对 concatenation/cascade hybrid KEM 给出（含 Coq/FCF 机器检查的）条件安全结果。准确问题：何种 KDF/RO 与 component assumption 才能保证一分量安全时组合安全；要求认证 public keys/ciphertexts，结论不能直接外推到协议身份与协商。[论文](https://eprint.iacr.org/2020/1364)

2. **Adam Petcher, Matthew Campagna, “Security of Hybrid Key Establishment using Concatenation,” 2023, IACR ePrint 2023/972.** 主要贡献：CtKDF 的机器检查 IND-CPA/IND-CCA 证明与标准部署解释。准确问题：主动安全要求把完整 public information/ciphertexts 以满足条件的编码放入 KDF `info`；经典 ROM 证明不等于 QROM，fresh key/reuse 条件不同。[论文](https://eprint.iacr.org/2023/972.pdf)

3. **Manuel Barbosa, Deirdre Connolly, João Diogo Duarte, Aaron Kaiser, Peter Schwabe, Karolin Varner, Bas Westerbaan, “X-Wing: The Hybrid KEM You've Been Looking For,” 2024, IACR Communications in Cryptology 1(1).** 主要贡献：具体 X25519+ML-KEM-768 构造；经典安全方向在 ROM 下由 strong-DH 等假设支撑，PQ 方向在标准模型下由 ML-KEM IND-CCA 与 SHA3 PRF 支撑。准确问题：generic combiner的 `ct` 绑定开销如何用具体构造优化；保证只适用于给定实例，不能泛化。[论文](https://doi.org/10.62056/a3qj89n4e)

4. **Lise Millerjord, Douglas Stebila, Camryn Steckel, “Split-key PRFs and Extended Hybrid Security for KEM Combiners,” 2026, IACR Communications in Cryptology 2(4).** 主要贡献：新 split-key PRF 构造及 extended hybrid KEM 模型。准确问题：真实系统可能用同一 component key 同时提供 standalone 与 combined decapsulation；传统只给 combined oracle、并假设 keys 独立的 IND-CCA 模型覆盖不足。[论文](https://www.douglas.stebila.ca/research/papers/CIC-MilSteSte26/)

5. **Bruno Blanchet, Charlie Jacomme, “Post-Quantum Sound CryptoVerif and Verification of Hybrid TLS and SSH Key-Exchanges,” 2024, IEEE CSF.** 主要贡献：证明 CryptoVerif 对经典网络交互的黑盒量子攻击者健全，并验证 IETF hybrid TLS/SSH drafts。准确问题：固定套件下 authentication、FS/PQ-FS 与 KDF/transcript 假设；TLS 模型明确排除算法协商、tickets、post-handshake auth，工具不覆盖 QROM。[论文](https://bblanche.gitlabpages.inria.fr/publications/BlanchetJacommeCSF24.pdf)

6. **Benjamin Benčina, Benjamin Dowling, Varun Maram, Keita Xagawa, “Post-Quantum Cryptographic Analysis of SSH,” 2025, IEEE Symposium on Security and Privacy.** 主要贡献：为完整 SSH 给出捕获 HNDL 的 PQ ACCE 分析，并在 QROM 中分析 hybrid KEX。准确问题：把孤立 KEX 提升到 secure-channel；说明协议内 ephemeral KEM 可只要求 IND-CPA，而非机械套用 IND-CCA。[论文](https://eprint.iacr.org/2025/684.pdf)

7. **Karthikeyan Bhargavan, Charlie Jacomme, Franziskus Kiefer, Rolfe Schmidt, “Formal Verification of the PQXDH Post-Quantum Key Agreement Protocol for End-to-End Secure Messaging,” 2024, USENIX Security.** 主要贡献：ProVerif + CryptoVerif 分析 PQXDH并协助修订规范。准确问题：public-key confusion、KEM re-encapsulation、KDF `info` 的 cross-protocol 作用、one-time/last-resort 混淆；提出/证明 Kyber 的 `SH-CR` binding 条件。[论文](https://www.usenix.org/conference/usenixsecurity24/presentation/bhargavan)

8. **Stefan-Lukas Gazdag, Sophia Grundner-Culemann, Tobias Guggemos, Tobias Heider, Daniel Loebenberger, “A Formal Analysis of IKEv2’s Post-Quantum Extension,” 2021, ACSAC.** 主要贡献：首个量子设定下 Minimal IKEv2 Tamarin 模型，验证单个 IKE_INTERMEDIATE。准确问题：额外轮次/密钥材料改变核心状态机；证明 secrecy/identity protection 等，但 fragmentation 为黑盒，未覆盖多 exchange、EAP/cert/PQ signature。[论文](https://www.mnm-team.org/pub/Publikationen/gggh21b/PDF-Version/gggh21b.pdf)

9. **Felix Linker, Ralf Sasse, David Basin, “A Formal Analysis of Apple’s iMessage PQ3 Protocol,” 2025, USENIX Security.** 主要贡献：Tamarin 对 ECDH+KEM ratchets 的无界嵌套状态进行细粒度 secrecy/auth、FS/PCS/HNDL 验证。准确问题：injective agreement/replay 保证需要额外 session-handling 假设；实现、会话层、prekey rollover 与完整 group/multi-device 行为不在证明内。[论文](https://www.usenix.org/conference/usenixsecurity25/presentation/linker)

10. **Cas Cremers, Caroline Fontaine, Charlie Jacomme, “A Logic and an Interactive Prover for the Computational Post-Quantum Security of Protocols,” 2022, IEEE Symposium on Security and Privacy.** 主要贡献：PQ-BC logic 与 PQ-Squirrel，机械化 KEM KEX、IKE 子协议和 PQ Signal/X3DH 类案例。准确问题：如何让 computational protocol proof 对量子攻击者健全；它不是自动化状态机或侧信道工具。[论文](https://eprint.iacr.org/2022/401.pdf)

11. **Peter Schwabe, Douglas Stebila, Thom Wiggers, “Post-Quantum TLS Without Handshake Signatures,” 2020, ACM CCS.** 主要贡献：KEMTLS，用 KEM 完成 server authentication，并在 multi-stage AKE 模型中分析。准确问题：KEM 替代签名改变认证发生时间、forward secrecy 与 stage-key freshness；不能把 TLS 1.3 的签名证明原样套用。[论文](https://eprint.iacr.org/2020/534.pdf)

12. **Felix Günther, Simon Rastikian, Patrick Towa, Thom Wiggers, “KEMTLS with Delayed Forward Identity Protection in (Almost) a Single Round Trip,” 2022, ACNS.** 主要贡献：用 medium-lived/long-term KEM key 改进 KEMTLS 的延迟与身份保护。准确问题：认证 key 的寿命与消息阶段决定何时获得 FS 和 server identity protection。[论文](https://eprint.iacr.org/2021/725)

13. **Jacqueline Brendel et al., “Post-Quantum Asynchronous Deniable Key Exchange and the Signal Handshake,” 2022, PKC.** 主要贡献：形式化 PQ 异步 deniable key exchange，并用 static/ephemeral KEM 与 designated-verifier signature 构造。准确问题：把 DH 机械替换为 KEM 会破坏异步 implicit mutual authentication、compromise security 或 deniability之间的平衡。[论文](https://www.douglas.stebila.ca/research/papers/PKC-BFGJS22/)

14. **Yevgeniy Dodis, Daniel Jost, Shuichi Katsumata, Thomas Prest, Rolfe Schmidt, “Triple Ratchet: A Bandwidth Efficient Hybrid-Secure Signal Protocol,” 2025, EUROCRYPT.** 主要贡献：在 Double Ratchet 上加入带宽均衡的 PQ ratchet，给出 hybrid secure messaging 论证。准确问题：稀疏 PQ 更新与丢包/非理想通信会扩大恢复延迟和重复大 ciphertext 的代价。[论文信息](https://researchr.org/publication/DodisJKPS25-0)

15. **Karthikeyan Bhargavan, Maxime Buyse, Graeme Connell, Franziskus Kiefer, Rolfe Schmidt, “A Formal Analysis of Signal’s Sparse Post-Quantum Ratchet Protocol and its Implementation,” 2026, ACM CCS（accepted，截至截止日）.** 主要贡献：hand-written ProVerif、F* runtime safety 与源码安全分析 artifact。准确问题：缩短抽象 ratchet 模型与真实实现之间的距离；最终出版版本的定理边界仍应以会议论文为准。[会议页](https://www.sigsac.org/ccs/CCS2026/program/accepted-papers.html) · [artifact](https://luneresearch.com/papers/0db36a85-6fa1-4e7d-9aef-e85df4db083c)

16. **Phillip Gajland, Vincent Hwang, Jonas Janneck, “Shadowfax: Hybrid Security and Deniability for AKEMs,” 2026, USENIX Security.** 主要贡献：black-box hybrid AKEM 与具体 Shadowfax，兼顾 hybrid confidentiality/authentication和 honest/dishonest receiver deniability。准确问题：普通 black-box hybrid 要继承 deniability 往往要求两个分量都 deniable，不符合 strongest-component 直觉；具体构造需深入假设层解决。[论文](https://www.usenix.org/conference/usenixsecurity26/presentation/gajland)

17. **Fabian Bäumer, Marcus Brinkmann, Jörg Schwenk, “Terrapin Attack: Breaking SSH Channel Integrity by Sequence Number Manipulation,” 2024, USENIX Security.** 主要贡献：对 SSH 前缀截断与扩展协商的真实攻击。准确问题：sequence-number manipulation 可删除已加密信道开头的扩展消息，降级认证算法/关闭缓解；它是 PQ migration 的直接邻接证据，不是 ML-KEM 密码分析。[论文](https://www.usenix.org/conference/usenixsecurity24/presentation/b%C3%A4umer)

18. **Daniel J. Bernstein et al., “KyberSlash: Exploiting Secret-Dependent Division Timings in Kyber Implementations,” 2025, IACR Transactions on Cryptographic Hardware and Embedded Systems.** 主要贡献：从 secret-dependent division timing 构造 plaintext-checking oracle 并在多平台恢复 Kyber keys。准确问题：源码/编译器/平台的变量时间行为破坏理想 decapsulation 与 implicit rejection 假设。[论文](https://eprint.iacr.org/2024/1049.pdf)

19. **Robin Leander Schröder, Stefan Gast, Qian Guo, “Divide and Surrender: Exploiting Variable Division Instruction Timing in HQC Key Recovery Attacks,” 2024, USENIX Security.** 主要贡献：共置 SMT timing attack，少量 traces 构造 oracle 并快速恢复 HQC key。准确问题：编译器生成的 operand-dependent division 击穿“参考实现恒定时间”假设。[论文](https://www.usenix.org/system/files/usenixsecurity24-schroder.pdf)

20. **Ilsun You, Jiyoon Kim, I Wayan Adi Juliawan Pawana, Yongho Ko, “Mitigating Security Vulnerabilities in 6G Networks: A Comprehensive Analysis of the DMRN Protocol Using SVO Logic and ProVerif,” 2024, Applied Sciences 14(21).** 主要贡献：对 DMRN PQ/PFS authentication进行 SVO 与 ProVerif分析。准确问题：MAC replay、HN masquerade、UE–SN mutual authentication不足；venue 与模型需独立复核。[论文](https://www.mdpi.com/2076-3417/14/21/9726)

21. **Yongho Ko, I Wayan Adi Juliawan Pawana, Ilsun You, “5G-AKA-HPQC: Hybrid Postquantum Cryptography Protocol for Quantum-Resilient 5G Primary Authentication With Forward Secrecy,” 2026, IEEE Internet of Things Journal.** 主要贡献：ECIES+PQC KEM 的 5G 主认证设计与 SVO/ProVerif评估。准确问题：同时追求三方 authentication、subscriber privacy与 FS；尚需用更强腐化、完整 SQN/roaming 和实现模型复核。[预印本](https://arxiv.org/abs/2502.02851)

22. **Céline Chevalier, Guirec Lebrun, Ange Martinelli, “Spilling-Cascade: an Optimal PKE Combiner for KEM Hybridization,” 2025, ACNS.** 主要贡献：先构造 robust IND-CPA PKE combiner，再经 FO 转换得到 IND-CCA KEM，并降低 bandwidth。准确问题：hybrid robustness 与通信开销的可证明折中；仍是构件级而非身份/协商证明。[论文](https://eprint.iacr.org/2023/898)

### 范围外但必要的奠基文献

23. **Federico Giacon, Felix Heuer, Bertram Poettering, “KEM Combiners,” 2018, PKC.** 定义 parallel/cascade 与 split-key PRF 路线，给出为何朴素 parallel 组合不自动主动安全的基础。本文只把它作为 2020 以后工作的前史。[论文](https://www.iacr.org/archive/pkc2018/10770204/10770204.pdf)

24. **Nina Bindel, Jacqueline Brendel, Marc Fischlin, Brian Goncalves, Douglas Stebila, “Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange,” 2019, PQCrypto.** 建立 hybrid KEM/AKE 与量子攻击时间线的基础框架。本文不把它计入 2020–2026 核心样本，只用于术语来源。[论文](https://eprint.iacr.org/2018/903)

---

## 结论

Hybrid PQC 研究的主问题已经从“是否能把两个 secret 拼起来”转向三个更难的层面：

1. **关系**：secret、pk、ct、identity、role、algorithm、session 是否唯一绑定；
2. **时间**：经典/PQ 长期与临时 key 在何时泄漏，量子攻击者何时出现，协议何时恢复；
3. **边界**：协商、会话层、API、编译器与侧信道是否被证明覆盖。

最值得优先开展的研究，是选一个真实迁移协议（TLS/SSH、MLS、Signal ratchet 或 5G AKA），同时交付：攻击者能力 lattice、Tamarin 状态模型、计算安全接口、实现/版本 provenance 和负向回归攻击。这样的工作比再增加一个脱离协商与实现的 `secrecy lemma` 更可能产生可复用、可发表且对标准化有影响的结果。

