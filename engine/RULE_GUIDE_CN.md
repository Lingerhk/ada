# Engine YAML 规则开发指南

语言：[English](RULE_GUIDE.md)

本文档面向需要在 ADAegis engine 模块中编写、调试和上线 YAML 检测规则的用户。engine 规则分为两层：

- Sigma 单事件规则：把一条 winlog 或 pktlog 原始日志匹配成 activity。
- Flow 多事件关联规则：把多个 activity 按时间窗口、字段关系、计数、缓存或 LDAP 上下文关联成 threat event。

推荐先写 Sigma 规则，确认能稳定产生活动，再写 Flow 规则做关联。Flow 规则引用的是 Sigma 规则的 `id`，不是原始事件字段。

## 规则目录

开发环境和仓库默认目录：

| 规则类型 | 仓库目录 | 运行时目录 | 说明 |
| --- | --- | --- | --- |
| winlog Sigma | `engine/rules/winlog` | `/home/adadmin/rules/winlog` | Windows 事件日志单事件检测。 |
| pktlog Sigma | `engine/rules/pktlog` | `/home/adadmin/rules/pktlog` | 网络/协议日志单事件检测。 |
| Flow | `engine/rules/flow` | `/home/adadmin/rules/flow` | 多事件、计数、winlog+pktlog 混合关联。 |

engine 启动时会加载运行时目录中的 `.yml` 文件。修改规则后需要触发热加载或重启 engine。

```shell
redis-cli PUBLISH ada:engine:reload reload
```

也可以向 engine 进程发送 `SIGHUP`。热加载会重新读取 Flow、winlog Sigma、pktlog Sigma 规则，并刷新 Redis 中的 Flow 字段缓存。

## 命名与 ID 约定

建议保持以下命名方式：

| 类型 | ID 示例 | 文件名示例 | 约束 |
| --- | --- | --- | --- |
| winlog Sigma | `winlog-0104-0001` | `0104-0001-sensitive_login_succ.yml` | Flow `multi_eve` 只能引用 `winlog-*`。 |
| pktlog Sigma | `pktlog-0200-0001` | `0200-0001-ldap_bind.yml` | Flow `multi_pkt` 只能引用 `pktlog-*`。 |
| Flow | `flow-0005` | `0005-sensitive_user_login.yml` | Flow ID 需要唯一，重复 ID 会被跳过。 |

规则加载阶段会校验：

- `tags` 至少包含一个元素。
- `level` 必须是 `info`、`low`、`medium`、`high`、`critical`，或数字 `1` 到 `5`。
- Flow `event_type` 必须是 `count`、`multi_eve`、`multi_pkt`、`multi_eve_pkt`。
- Flow `sigma_rules` 最多 16 个。
- Flow `win_size` 必须能解析，且不能超过 6 小时。
- Flow `match_by` 中的 `$sN` 不能超过 `sigma_rules` 的数量。

## Sigma 单事件规则

Sigma 规则负责匹配单条原始日志。winlog 和 pktlog 共用同一套 YAML 结构，区别主要在 `id` 前缀、放置目录和事件字段。

### 基础模板

```yaml
title: Sensitive User Login Succeeded
id: winlog-0104-0001
status: experimental
description: Remote logon by a sensitive user
references:
  - https://example.com/rule-reference
author: ada
date: 2026/05/04
modified: 2026/05/04
tags:
  - TA0007
  - attack.t1078
logsource: winlog
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: NTLM
  filter_local_ip:
    IpAddress:
      - "::1"
      - "127.0.0.1"
  filter_machine_account:
    TargetUserName|endswith: "$"
  condition: selection and not filter_local_ip and not filter_machine_account
fields:
  - Hostname
  - TargetDomainName
  - TargetUserName
  - TargetUserSid
  - IpAddress
unique_fields:
  - Hostname
  - TargetUserName
  - IpAddress
level: low
```

### Sigma 顶层字段

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `title` | 建议 | 展示在 activity 标题中。 |
| `id` | 是 | 规则唯一 ID。建议 winlog 使用 `winlog-*`，pktlog 使用 `pktlog-*`。 |
| `status` | 建议 | 规则状态，例如 `experimental`、`test`、`stable`。 |
| `description` | 建议 | 告警说明，会进入 activity 元信息。 |
| `references` | 否 | 参考链接列表。 |
| `author` | 否 | 作者。 |
| `date` | 否 | 创建日期。 |
| `modified` | 否 | 修改日期。 |
| `tags` | 是 | 至少一个标签。`tags[0]` 会作为 ATT&CK 或分类主标签使用。 |
| `logsource` | 是 | 支持字符串或映射。现有内置规则常用 `winlog`、`pktlog`。 |
| `detection` | 是 | 匹配逻辑。必须包含 `condition`。 |
| `fields` | 建议 | 命中后从原始日志提取到 activity 的字段。Flow 使用的字段也需要可被提取。 |
| `unique_fields` | 建议 | 生成 activity `unique_id` 的字段。旧 Flow 未配置 `cache_key` 时会用它做实例分桶。 |
| `rdx_key` | 否 | 内置上下文缓存 key，主要用于给后续规则提供 Redis set 上下文。 |
| `level` | 是 | 风险等级。数字 `1..5` 会转换为 `info..critical`。 |

### `logsource` 写法

现有 engine 支持两种写法。

简写：

```yaml
logsource: winlog
```

映射写法：

```yaml
logsource:
  product: windows
  category: process_creation
  service: security
  definition: "optional text"
```

当前仓库内置规则主要用简写。新规则建议继续使用 `winlog` 或 `pktlog`，便于按目录和前缀维护。

### `detection` 结构

`detection` 由多个命名 selection/filter/keyword 和一个 `condition` 组成。

```yaml
detection:
  selection_event:
    EventID: 4624
    LogonType: 3
  selection_auth:
    AuthenticationPackageName:
      - NTLM
      - Kerberos
  filter_loopback:
    IpAddress:
      - "::1"
      - "127.0.0.1"
  condition: selection_event and selection_auth and not filter_loopback
```

命名块本身不区分 `selection`、`filter` 的语义，真正语义由 `condition` 决定。工程习惯上：

- 用 `selection_*` 表示正向命中条件。
- 用 `filter_*` 表示排除误报条件。
- 用 `keyword*` 表示关键字匹配条件。

### 字段精确匹配

```yaml
detection:
  selection:
    EventID: 4624
    TargetUserName: administrator
  condition: selection
```

字符串匹配默认是精确匹配。数字字段可以写成数字，事件中的数字字符串、JSON number、整数类型都可参与数字匹配。

```yaml
detection:
  selection:
    EventID: 4624
    LogonType: 3
  condition: selection
```

注意：规则选择值当前支持字符串、整数、字符串列表、整数列表。不要在 selection 值里写布尔值或混合类型列表。

### 字符串修饰符

字段名可以使用 `|` 链接修饰符。

| 修饰符 | 示例 | 说明 |
| --- | --- | --- |
| `contains` | `CommandLine|contains: mimikatz` | 字段包含指定字符串。 |
| `startswith` | `Image|startswith: C:\Windows\` | 字段以前缀开始。 |
| `endswith` | `TargetUserName|endswith: "$"` | 字段以后缀结束。 |
| `re` | `CommandLine|re: "(?i)sekurlsa"` | 使用正则表达式。 |
| `all` | `CommandLine|contains|all: [...]` | 列表中所有字符串都需要命中。 |

示例：

```yaml
detection:
  selection_cmd:
    CommandLine|contains|all:
      - powershell
      - EncodedCommand
  selection_path:
    Image|endswith:
      - "\\powershell.exe"
      - "\\pwsh.exe"
  condition: selection_cmd or selection_path
```

同一个字段使用多个互斥字符串修饰符时，最后一个互斥修饰符生效。建议不要同时写 `contains`、`startswith`、`endswith`、`re`。

### 列表匹配

字符串列表默认是 OR。

```yaml
detection:
  selection:
    AuthenticationPackageName:
      - NTLM
      - Kerberos
  condition: selection
```

整数列表也默认是 OR。

```yaml
detection:
  selection:
    EventID:
      - 4624
      - 4625
  condition: selection
```

列表不要混用字符串和数字。

### 通配符和正则

字符串值中可以使用 `*` 通配。

```yaml
detection:
  selection:
    CommandLine: "*powershell*EncodedCommand*"
  condition: selection
```

也可以使用 `|re`：

```yaml
detection:
  selection:
    CommandLine|re: "(?i)(mimikatz|sekurlsa)"
  condition: selection
```

如果字符串以 `/` 包裹，也会按正则模式处理。为了可读性，建议新规则统一使用 `|re`。

### 多个 selection 的条件表达式

`condition` 支持：

- `and`
- `or`
- `not`
- 括号
- `1 of selection*`
- `all of selection*`
- `1 of them`
- `all of them`

示例：

```yaml
detection:
  selection_4624:
    EventID: 4624
  selection_ntlm:
    AuthenticationPackageName: NTLM
  filter_machine:
    TargetUserName|endswith: "$"
  condition: selection_4624 and selection_ntlm and not filter_machine
```

通配 selection：

```yaml
detection:
  selection_cmd:
    CommandLine|contains: cmd.exe
  selection_powershell:
    CommandLine|contains: powershell
  filter_system:
    SubjectUserSid: S-1-5-18
  condition: 1 of selection* and not filter_system
```

组合括号：

```yaml
detection:
  selection_a:
    EventID: 4624
  selection_b:
    EventID: 4648
  filter_local:
    IpAddress: "127.0.0.1"
  condition: (selection_a or selection_b) and not filter_local
```

### selection 列表

一个 selection 可以写成多个字段映射的列表，列表内是 OR。

```yaml
detection:
  selection:
    - EventID: 4624
      LogonType: 3
    - EventID: 4648
      ProcessName|endswith: "\\runas.exe"
  condition: selection
```

上例表示任意一个 map 命中即可。

### keyword 规则

名称以 `keyword` 开头的 detection 项会按事件关键字匹配。底层事件需要实现 `Keywords()`，适合有全文/关键字字段的事件类型。

```yaml
detection:
  keywords:
    - mimikatz
    - sekurlsa
  condition: keywords
```

keyword 列表仅支持字符串列表。它会以包含式匹配关键字文本。

### 兼容的旧 `key/value` 结构

engine 对历史测试规则中的 `key/value` 形态做了兼容归一化，但新规则不要继续使用这种写法。

旧写法示意：

```yaml
detection:
  selection:
    - key: EventID
      value: 4624
  condition: selection
```

新规则应写成标准 map：

```yaml
detection:
  selection:
    EventID: 4624
  condition: selection
```

### `fields` 与 Flow 字段

`fields` 控制 activity 中保留哪些原始字段。Flow `match_by`、`cache_key`、`unique_filter` 依赖的字段必须能从 activity 取到。

```yaml
fields:
  - Hostname
  - TargetDomainName
  - TargetUserName
  - IpAddress
```

Flow 加载时会把 `match_by` 和 `cache_key` 中引用的字段合并进相关 Sigma 规则的字段集合，但建议在 Sigma 规则里主动写清楚，方便 review 和调试。

### `unique_fields`

`unique_fields` 用于生成 Sigma activity 的 `unique_id`。旧 Flow 未配置 `detection.cache_key` 时，会使用这个 `unique_id` 作为 Flow instance key。

```yaml
unique_fields:
  - Hostname
  - TargetUserName
  - IpAddress
```

建议：

- 单事件告警可以用能代表同一行为实体的字段组合。
- 需要 Flow 混合关联时，优先在 Flow 中配置 `cache_key`，不要依赖不同 Sigma 规则各自的 `unique_id`。
- 字段为空会降低关联稳定性。开发时必须用模拟日志覆盖这些字段。

### `rdx_key`

`rdx_key` 是内置规则缓存能力，主要用于把某些命中的 activity 写入 Redis set，给后续 `$v.cache` 或上下文判断使用。

```yaml
rdx_key: rule_cache:aduser_info
```

注意：

- 当前这是内部约定能力，不是通用 KV DSL。
- 新规则优先用 Flow `cache_key` 控制实例分桶，用 `$v.cache` 或 `$v.ldap` 做上下文集合判断。
- 不要随意新增未被代码消费的 `rdx_key`，否则只会增加维护成本。

## Flow 多事件关联规则

Flow 规则负责将 Sigma activity 关联为 threat event。Flow 不直接匹配原始日志，它只消费 Sigma 命中后的 activity。

### 基础模板

```yaml
title: Sensitive User Login
id: flow-0005
status: experimental
description: Sensitive domain account logged in remotely
references:
  - https://example.com/reference
author: ada
date: 2026/05/04
modified: 2026/05/04
tags:
  - TA0007
  - attack.t1078
logsource: flow
detection:
  event_type: multi_eve
  win_size: 60s
  sorted: false
  sigma_rules:
    - winlog-0104-0001
  match_by: "$s1.TargetUserName in $v.cache.key_ada:engine:%s:sensitive_users($s1.TargetDomainName)"
unique_filter:
  - $s1.TargetDomainName
  - $s1.TargetUserName
  - $s1.IpAddress
  - ttl_3600
level: medium
```

### Flow 顶层字段

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `title` | 建议 | threat event 标题。 |
| `id` | 是 | Flow 唯一 ID。重复 ID 会被跳过。 |
| `status` | 建议 | 规则状态。 |
| `enable` | 否 | 默认启用。显式 `enable: false` 才禁用。 |
| `description` | 建议 | threat event 描述。 |
| `references` | 否 | 参考链接。 |
| `author` | 否 | 作者。 |
| `date` | 否 | 创建日期。 |
| `modified` | 否 | 修改日期。 |
| `tags` | 是 | 至少一个标签。 |
| `logsource` | 是 | 必须是 `flow`。 |
| `detection` | 是 | Flow 关联定义。 |
| `unique_filter` | 否 | threat event 去重。 |
| `level` | 是 | 风险等级。 |

### `event_type`

| 类型 | Sigma 引用要求 | 使用场景 |
| --- | --- | --- |
| `count` | 通常 1 个 Sigma，也支持按 `$sN` 指定 | 同窗口同类行为达到阈值，例如爆破。 |
| `multi_eve` | 只能引用 `winlog-*` | 多条 Windows 事件日志关联。 |
| `multi_pkt` | 只能引用 `pktlog-*` | 多条网络/协议日志关联。 |
| `multi_eve_pkt` | 必须同时引用 `winlog-*` 和 `pktlog-*` | winlog 与 pktlog 混合关联。 |

如果类型和 Sigma 前缀不匹配，规则会在加载阶段被忽略。

### `sigma_rules` 与 `$sN`

`sigma_rules` 的顺序决定 `match_by` 中 `$sN` 的含义。

```yaml
detection:
  sigma_rules:
    - winlog-0000-0001  # $s1
    - winlog-0102-0001  # $s2
  match_by: "$s1.TargetUserName == $s2.SubjectUserName AND $s1.Hostname == $s2.Hostname"
```

规则：

- `$s1` 指向 `sigma_rules[0]`。
- `$s2` 指向 `sigma_rules[1]`。
- 最大支持 `$s16`。
- 字段名大小写需要和 activity 中字段一致。
- 引用不存在的 `$sN` 会导致 Flow 规则加载失败。

### `win_size`

`win_size` 是 Flow 的时间窗口。

```yaml
detection:
  win_size: 30s
```

常用单位：

- `s` 秒
- `m` 分钟
- `h` 小时

最大窗口是 6 小时。窗口越大，Redis 中保留的 activity 越多，关联成本越高。除非确实需要跨长时间行为链，建议从 `30s`、`60s`、`5m` 这类窗口开始。

### `sorted`

```yaml
detection:
  sorted: false
```

`sorted` 控制是否要求 activity 按 `sigma_rules` 顺序出现。

- `false`：不强制顺序。适合多数关联规则。
- `true`：要求事件顺序与 `sigma_rules` 顺序一致。适合明确的阶段性行为链。

不写时默认为 `false`。

### `match_by` 关系表达式

Flow `match_by` 支持关系比较、集合判断、计数表达式和布尔组合。

关系比较：

```yaml
match_by: "$s1.TargetUserName == $s2.SubjectUserName"
```

支持操作符：

| 操作符 | 说明 |
| --- | --- |
| `==` | 字符串相等或数字相等。 |
| `!=` | 不相等。 |
| `>` | 大于。 |
| `>=` | 大于等于。 |
| `<` | 小于。 |
| `<=` | 小于等于。 |
| `in` | 左值在右侧集合中。 |

常量比较：

```yaml
match_by: "$s1.LogonType == 3"
```

注意：Flow 条件解析会移除空格。常量中不要包含空格。需要匹配复杂字符串时，优先在 Sigma 层完成匹配，再让 Flow 做字段关系。

### `match_by` 布尔表达式

Flow `match_by` 支持 AST 解析。

```yaml
match_by: "($s1.UserName == $s2.TargetUserName OR $s1.UserSid == $s2.TargetUserSid) AND NOT ($s1.TargetDomainName == blocked)"
```

规则：

- `AND`、`OR`、`NOT` 大小写不敏感。
- 支持括号。
- 默认优先级：`NOT > AND > OR`。
- `$v.cache.key_...(...)` 和 `$v.ldap.key_...(...)` 中的括号属于 key 模板，不会被误解析为布尔分组。

建议复杂规则显式加括号，降低 review 成本。

### `count` 规则

`event_type: count` 使用计数表达式。

总数计数：

```yaml
detection:
  event_type: count
  win_size: 30s
  sigma_rules:
    - winlog-0101-0002
  match_by: "$s1._count >= 5"
```

等价写法：

```yaml
match_by: "len($s1) >= 5"
```

字段非空出现次数：

```yaml
match_by: "len($s1.TargetUserName) >= 5"
```

字段去重计数：

```yaml
match_by: "len(distinct($s1.TargetUserName)) >= 3"
```

兼容写法：

```yaml
match_by: "$s1.TargetUserName._count >= 3"
```

所有 count 写法都支持：

- `==`
- `!=`
- `>`
- `>=`
- `<`
- `<=`

字段去重前会做 `trim + lower`。适合口令喷洒、账户枚举、同源多目标访问等场景。

### `$v.slice` 静态集合

`$v.slice` 用 JSON 字符串数组表示静态集合。

```yaml
match_by: "$s1.LogonType in $v.slice.[\"3\",\"10\"]"
```

注意：

- 右侧必须是 JSON 字符串数组。
- 解析会移除空格，所以数组值不要依赖空格。
- 如果集合经常变化，使用 `$v.cache` 或 `$v.ldap`。

### `$v.cache` Redis 集合

`$v.cache` 用 Redis set 做上下文判断。

```yaml
match_by: "$s1.TargetUserName in $v.cache.key_ada:engine:%s:sensitive_users($s1.TargetDomainName)"
```

语法：

```text
$sN.Field in $v.cache.key_<redis-key-template>(<param-list>)
```

规则：

- 模板必须以 `key_` 开头。
- `key_` 后是真实 Redis key 模板。
- 每个 `%s` 必须对应一个参数。
- 参数必须是 `$sN.Field`。
- 参数值会 `trim + lower`。
- 当参数字段是 `TargetDomainName` 时，engine 会结合 `Hostname` 做域名归一化。

示例：

```yaml
match_by: "$s1.TargetUserName in $v.cache.key_ada:engine:%s:honeypot_accounts($s1.TargetDomainName)"
```

对应 Redis set：

```shell
redis-cli SADD ada:engine:example.com:honeypot_accounts fake_admin
```

也可以使用无参数固定 key：

```yaml
match_by: "$s1.TargetUserName in $v.cache.key_ada:engine:global:vip_users"
```

### `$v.ldap` 异步 LDAP 集合

`$v.ldap` 与 `$v.cache` 语法一致，但 cache miss 时会触发 tasker 异步 LDAP 查询。

```yaml
match_by: "$s1.TargetUserName in $v.ldap.key_ada:engine:%s:sensitive_users($s1.TargetDomainName)"
```

运行行为：

1. FlowMatcher 先用模板生成 Redis set key。
2. 执行 `SMEMBERS`。
3. set 存在且包含左值时，规则同步命中。
4. set 不存在或为空时，engine 写入 `ada:engine:ldap_search_pending:<hash>`，TTL 60 秒。
5. engine 向 `ada:engine:ldap_search_channel` 发布 LDAP 查询请求。
6. tasker 异步读取域 LDAP 账号，查询 LDAP，并把结果写回 Redis set，TTL 60 秒。
7. 当前 FlowMatcher 周期不会等待 LDAP；下一个周期会使用回填后的 Redis set。

支持的 LDAP set：

| Redis key 形态 | 查询内容 |
| --- | --- |
| `ada:engine:<domain>:sensitive_users` | 敏感用户，例如 `adminCount=1` 用户。 |
| `ada:engine:<domain>:sensitive_groups` | 内置敏感组。 |
| `ada:engine:<domain>:sensitive_computers` | DC/RODC 等敏感计算机。 |

不支持自动 LDAP 查询的 set：

| Redis key 形态 | 建议 |
| --- | --- |
| `ada:engine:<domain>:honeypot_accounts` | 用 `$v.cache`，由人工或外部任务预填 Redis set。 |

开发建议：

- `$v.ldap` 首次 miss 后通常需要再等一个 FlowMatcher 周期。
- 测试规则时可先手动 `SADD` Redis set 验证表达式，再清空 set 验证 LDAP miss 和回填链路。
- 不要把 LDAP 查询放进 Sigma 单事件规则。LDAP 上下文只应在 Flow 层使用。

### `cache_key` Flow 实例分桶

`detection.cache_key` 决定 Sigma activity 写入哪个 Flow instance。它是 winlog+pktlog 混合关联最重要的配置。

没有 `cache_key` 时，engine 使用 Sigma activity 的 `unique_id`。不同 Sigma 规则的 `unique_id` 字段通常不一致，混合关联容易分不到同一个 instance。

示例：

```yaml
detection:
  event_type: multi_eve_pkt
  win_size: 60s
  sorted: false
  sigma_rules:
    - winlog-0104-0001
    - pktlog-0200-0001
  cache_key:
    winlog-0104-0001:
      - TargetDomainName|domain
      - TargetUserName|lower|trim
      - IpAddress|ip
    pktlog-0200-0001:
      - Domain|domain
      - UserName|lower|trim
      - SrcIp|ip
  match_by: "$s1.TargetUserName == $s2.UserName AND $s1.TargetDomainName == $s2.Domain AND $s1.IpAddress == $s2.SrcIp"
```

字段规格：

```text
<field>|<normalizer>|<normalizer>
```

支持的 normalizer：

| normalizer | 说明 |
| --- | --- |
| `trim` | 去除首尾空白。 |
| `lower` | 转小写。 |
| `domain` | 域名归一化，例如结合 `dc01.example.com` 把 `EXAMPLE` 归一化到 `example.com`。 |
| `ip` | 使用 IP parser 归一化 IP 字符串。 |

规则：

- `cache_key` 的 key 必须是 `sigma_rules` 中存在的 Sigma ID。
- 每个 Sigma ID 至少配置一个字段。
- 字段为空会导致该 activity 不写入对应 Flow instance。
- 不同 Sigma 的字段数量不必相同，但语义上应能落到同一实体。
- 参与 `cache_key` 的字段会自动加入相关 Sigma 的提取字段集合。

建议：

- `multi_eve_pkt` 一般必须配置 `cache_key`。
- 用户维度推荐 `domain + username`。
- 主机维度推荐 `hostname` 或 `domain + computer`。
- 网络维度推荐 `ip` normalizer。
- 不要把高基数字段和随机字段放进 `cache_key`，例如进程 ID、临时端口、Mongo ID。

### `unique_filter` 告警去重

`unique_filter` 用于 threat event 去重，避免同一 Flow 反复生成相同告警。

```yaml
unique_filter:
  - $s1.TargetDomainName
  - $s1.TargetUserName
  - $s1.IpAddress
  - ttl_3600
```

规则：

- 字段必须使用 `$sN.Field`。
- `ttl_N` 设置去重 key 的 TTL，单位是秒。
- `ttl_0` 表示不设置过期时间，慎用。
- 去重字段来自实际参与命中的 activity 组合。

建议：

- 在线环境优先设置正数 TTL，例如 `ttl_300`、`ttl_3600`。
- 去重字段选择能代表同一个安全事件的最小集合。
- 不要把时间戳、随机 ID、Mongo ID 放入 `unique_filter`。

## 场景化规则示例

### 1. 单条 winlog 触发 activity

```yaml
title: RDP Login Failed
id: winlog-0101-0002
status: experimental
description: Failed remote logon
tags:
  - TA0006
logsource: winlog
detection:
  selection:
    EventID: 4625
    LogonType: 3
  filter_machine:
    TargetUserName|endswith: "$"
  condition: selection and not filter_machine
fields:
  - Hostname
  - TargetDomainName
  - TargetUserName
  - IpAddress
unique_fields:
  - Hostname
  - TargetUserName
  - IpAddress
level: low
```

适合验证单事件字段提取是否正确。

### 2. 单条 pktlog 触发 activity

```yaml
title: LDAP Simple Bind
id: pktlog-0200-0001
status: experimental
description: LDAP simple bind over network traffic
tags:
  - TA0006
logsource: pktlog
detection:
  selection:
    Protocol: ldap
    Action: bind
    AuthType: simple
  filter_empty_user:
    UserName: ""
  condition: selection and not filter_empty_user
fields:
  - Hostname
  - Domain
  - UserName
  - SrcIp
  - DstIp
  - DstPort
unique_fields:
  - Domain
  - UserName
  - SrcIp
level: info
```

pktlog 字段应以实际 sensor 上报字段为准。不要在规则里使用不存在的字段名。

### 3. 失败登录爆破

```yaml
title: RDP Login Brute Force
id: flow-1001
status: experimental
description: Multiple failed RDP logons in a short window
tags:
  - TA0006
  - attack.t1110
logsource: flow
detection:
  event_type: count
  win_size: 60s
  sigma_rules:
    - winlog-0101-0002
  match_by: "$s1._count >= 5"
unique_filter:
  - $s1.Hostname
  - $s1.IpAddress
  - ttl_600
level: medium
```

如果需要检测同一 IP 尝试多个账号：

```yaml
match_by: "len(distinct($s1.TargetUserName)) >= 5"
```

### 4. 多条 winlog 关联

```yaml
title: SAMR Sensitive Information Discovery
id: flow-1002
status: experimental
description: User logon followed by SAMR discovery on the same host
tags:
  - TA0007
logsource: flow
detection:
  event_type: multi_eve
  win_size: 60s
  sorted: false
  sigma_rules:
    - winlog-0000-0001
    - winlog-0102-0001
  match_by: "$s1.TargetUserName == $s2.SubjectUserName AND $s1.Hostname == $s2.Hostname"
unique_filter:
  - $s1.Hostname
  - $s1.TargetUserName
  - ttl_1800
level: high
```

### 5. 多条 pktlog 关联

```yaml
title: LDAP Bind Followed By SAMR Query
id: flow-1003
status: experimental
description: Same source performs LDAP bind and SAMR query
tags:
  - TA0007
logsource: flow
detection:
  event_type: multi_pkt
  win_size: 60s
  sorted: true
  sigma_rules:
    - pktlog-0200-0001
    - pktlog-0200-0002
  cache_key:
    pktlog-0200-0001:
      - Domain|domain
      - UserName|lower|trim
      - SrcIp|ip
    pktlog-0200-0002:
      - Domain|domain
      - UserName|lower|trim
      - SrcIp|ip
  match_by: "$s1.Domain == $s2.Domain AND $s1.UserName == $s2.UserName AND $s1.SrcIp == $s2.SrcIp"
level: medium
```

### 6. winlog + pktlog 混合关联

```yaml
title: Sensitive User Login With LDAP Bind
id: flow-1004
status: experimental
description: Sensitive user login confirmed by LDAP bind traffic
tags:
  - TA0006
  - attack.t1078
logsource: flow
detection:
  event_type: multi_eve_pkt
  win_size: 120s
  sorted: false
  sigma_rules:
    - winlog-0104-0001
    - pktlog-0200-0001
  cache_key:
    winlog-0104-0001:
      - TargetDomainName|domain
      - TargetUserName|lower|trim
      - IpAddress|ip
    pktlog-0200-0001:
      - Domain|domain
      - UserName|lower|trim
      - SrcIp|ip
  match_by: "($s1.TargetUserName == $s2.UserName AND $s1.TargetDomainName == $s2.Domain) AND $s1.IpAddress == $s2.SrcIp"
unique_filter:
  - $s1.TargetDomainName
  - $s1.TargetUserName
  - $s1.IpAddress
  - ttl_3600
level: high
```

这是 `multi_pkt_winlog` 需求对应的推荐写法。关键点是 `event_type: multi_eve_pkt` 加 `cache_key`，确保不同日志源进入同一个 Flow instance。

### 7. LDAP 敏感用户判断

```yaml
title: LDAP Sensitive User Remote Login
id: flow-1005
status: experimental
description: Remote login by user found in LDAP sensitive_users set
tags:
  - TA0006
  - attack.t1078
logsource: flow
detection:
  event_type: multi_eve
  win_size: 60s
  sigma_rules:
    - winlog-0104-0001
  match_by: "$s1.TargetUserName in $v.ldap.key_ada:engine:%s:sensitive_users($s1.TargetDomainName)"
unique_filter:
  - $s1.TargetDomainName
  - $s1.TargetUserName
  - $s1.IpAddress
  - ttl_3600
level: high
```

首次 miss 会触发异步 LDAP 查询。测试时如果要立即验证命中，可先手动填充：

```shell
redis-cli SADD ada:engine:example.com:sensitive_users administrator
redis-cli EXPIRE ada:engine:example.com:sensitive_users 60
```

### 8. 蜜罐账号判断

```yaml
title: Honeypot Account Login
id: flow-1006
status: experimental
description: Login by preconfigured honeypot account
tags:
  - TA0006
logsource: flow
detection:
  event_type: multi_eve
  win_size: 60s
  sigma_rules:
    - winlog-0104-0001
  match_by: "$s1.TargetUserName in $v.cache.key_ada:engine:%s:honeypot_accounts($s1.TargetDomainName)"
level: critical
```

蜜罐账号不是自动 LDAP 查询集合，需要由人工、任务或外部同步流程写入 Redis。

## 模拟日志与端到端验证

### 通过接收端口模拟日志

server 端接收 syslog 后会把日志写入 Redis 队列。测试时可以用 UDP syslog 格式发送 JSON。

```python
import json
import socket
import time

event = {
    "@timestamp": int(time.time() * 1000),
    "Hostname": "dc01.example.com",
    "EventID": 4624,
    "LogonType": 3,
    "AuthenticationPackageName": "NTLM",
    "TargetDomainName": "EXAMPLE",
    "TargetUserName": "administrator",
    "TargetUserSid": "S-1-5-21-1-2-3-500",
    "IpAddress": "192.168.7.5",
}

payload = "<14>May  4 12:00:00 dc01 ADASensor: " + json.dumps(event)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(payload.encode(), ("192.168.7.2", 514))
```

具体端口以 test 环境的 server 配置为准。pktlog 同理，只是 JSON 字段应匹配 pktlog 规则。

### 直接写 Redis 队列

开发环境也可以绕过接收端，直接写 Redis 队列。只建议用于本地或 test 环境定位 engine。

```shell
redis-cli LPUSH ada:evelog_queue '{"@timestamp":1714800000000,"Hostname":"dc01.example.com","EventID":4624,"LogonType":3,"AuthenticationPackageName":"NTLM","TargetDomainName":"EXAMPLE","TargetUserName":"administrator","TargetUserSid":"S-1-5-21-1-2-3-500","IpAddress":"192.168.7.5"}'
```

pktlog 队列：

```shell
redis-cli LPUSH ada:pktlog_queue '{"@timestamp":1714800000000,"Hostname":"dc01.example.com","Protocol":"ldap","Action":"bind","AuthType":"simple","Domain":"EXAMPLE","UserName":"administrator","SrcIp":"192.168.7.5","DstIp":"192.168.7.2","DstPort":389}'
```

### 验证 activity

检查 MongoDB：

```shell
mongosh db_ada --eval 'db.tb_alert_activity.find().sort({_id:-1}).limit(5).pretty()'
```

检查 ES：

```shell
curl -s 'http://127.0.0.1:9200/ada-activity/_search?size=5&sort=@timestamp:desc'
```

### 验证 Flow instance

查看 Flow 映射：

```shell
redis-cli HGETALL ada:engine:flow_rule_map
```

查看活跃 instance：

```shell
redis-cli SMEMBERS ada:engine:active:flow-1004
```

查看 instance 内 activity：

```shell
redis-cli ZRANGE 'ada:engine:instance:flow-1004_<instance_key>' 0 -1 WITHSCORES
```

### 验证 threat event

```shell
mongosh db_ada --eval 'db.tb_alert_event.find().sort({_id:-1}).limit(5).pretty()'
```

也可以检查通知队列：

```shell
redis-cli LRANGE ada:server:notify_queue 0 5
```

### 验证 `$v.ldap`

先清理缓存：

```shell
redis-cli DEL ada:engine:example.com:sensitive_users
```

触发规则后检查 pending key：

```shell
redis-cli --scan --pattern 'ada:engine:ldap_search_pending:*'
```

检查异步回填：

```shell
redis-cli SMEMBERS ada:engine:example.com:sensitive_users
redis-cli TTL ada:engine:example.com:sensitive_users
```

如果没有回填，检查 tasker 日志中 LDAP 账号读取、绑定、查询和写回是否成功。

## 常见问题

### 规则没有加载

检查：

- 文件扩展名是否为 `.yml`。
- `tags` 是否为空。
- `level` 是否合法。
- Flow `logsource` 是否为 `flow`。
- Flow `event_type` 是否合法。
- Flow `win_size` 是否超过 6 小时。
- Flow `match_by` 是否引用不存在的 `$sN`。
- `cache_key` 是否引用了不存在的 Sigma ID。

### Sigma 命中不了

检查：

- 原始日志字段名是否和规则字段一致。
- 数字字段是否被写成字符串但无法转换为整数。
- selection 列表是否混合了字符串和数字。
- 规则是否误用了布尔值。
- `condition` 是否把 filter 写成了正向条件。
- pktlog 字段是否与当前 sensor 上报字段一致。

### Flow 没有生成 event

检查：

- Sigma activity 是否已生成。
- `ada:engine:flow_rule_map` 是否有 Sigma ID 到 Flow ID 的映射。
- activity 是否写入 `ada:engine:instance:<flow_id>_<instance_key>`。
- `cache_key` 字段是否为空。
- `match_by` 中字段是否存在于 activity。
- `unique_filter` 是否把重复事件过滤掉。
- `win_size` 是否过短。
- `sorted: true` 是否导致顺序不满足。

### `multi_eve_pkt` 不命中

优先检查 `cache_key`：

- winlog 和 pktlog 是否能归一到同一个用户、主机、IP 或域。
- 域名是否一边是 NetBIOS 名，一边是 FQDN。需要使用 `domain` normalizer。
- 用户名是否大小写不一致。需要使用 `lower|trim`。
- IP 是否格式不一致。需要使用 `ip`。
- 是否把临时端口、进程 ID 这类不稳定字段放进了 `cache_key`。

### `$v.cache` 不命中

检查：

- Redis key 是否和模板生成的一致。
- set 中元素是否与左值归一化后的内容一致。
- 模板 `%s` 数量是否等于参数数量。
- 参数字段是否为空。
- `TargetDomainName` 是否能结合 `Hostname` 归一化为期望域名。

### `$v.ldap` 不命中

检查：

- Redis set 是否已经存在。如果存在但为空，FlowMatcher 仍会触发 miss。
- `ada:engine:ldap_search_pending:<hash>` 是否在 60 秒内阻止了重复查询。
- tasker 是否启动并订阅 `ada:engine:ldap_search_channel`。
- 域 LDAP 账号是否已写入 Redis。
- 域控是否可访问。
- 使用的 set 是否是支持的 `sensitive_users`、`sensitive_groups`、`sensitive_computers`。

### ES 没有 activity 文档

Sigma 命中后 MongoDB activity 和 ES activity 是两条写入链路。ES bulk writer 是批量写入，可能有几秒延迟。

检查：

- MongoDB `tb_alert_activity` 是否有记录。
- engine 日志是否有 ES bulk retry 或 dropped batch。
- ES index `ada-activity` 是否存在。
- ES 服务是否可访问。

## 规则开发 Checklist

上线前建议逐项确认：

- 规则 ID 唯一，前缀符合目录和类型。
- `tags` 非空，`level` 合法。
- Sigma `condition` 覆盖正向 selection 和误报 filter。
- Sigma `fields` 包含展示、Flow、`unique_fields` 所需字段。
- Flow `event_type` 和 Sigma 前缀匹配。
- Flow `sigma_rules` 顺序和 `$sN` 使用一致。
- Flow `win_size` 与攻击行为时间跨度匹配。
- `multi_eve_pkt` 已配置 `cache_key`。
- `cache_key` 使用了必要 normalizer。
- `$v.cache` 和 `$v.ldap` 的 Redis key 模板能实际生成。
- `unique_filter` 使用稳定字段，并设置合理 TTL。
- 使用 mock 日志验证了 Sigma activity。
- 使用 mock 日志验证了 Flow threat event。
- 使用真实或模拟缓存验证了 `$v.cache`。
- 如使用 `$v.ldap`，验证了 miss、异步查询、回填、下一轮命中。

## 推荐开发流程

1. 明确检测场景和需要的原始字段。
2. 先写 winlog 或 pktlog Sigma 规则。
3. 用 mock 日志验证 `tb_alert_activity` 中的 `fields` 是否正确。
4. 如果只需要单事件告警，到这里即可进入 review。
5. 如果需要关联，编写 Flow 规则并决定 `event_type`。
6. 为 `multi_eve_pkt` 或字段不一致的关联配置 `cache_key`。
7. 用最小 mock 数据触发每个 Sigma activity。
8. 检查 Flow instance 是否落在同一个 Redis key。
9. 检查 `match_by` 是否命中并生成 `tb_alert_event`。
10. 增加 `unique_filter`，验证重复日志不会刷屏。
11. 触发热加载，在 test 环境做端到端验证。
12. 把测试用规则、mock 数据和预期结果记录在 PR 或变更说明中。
