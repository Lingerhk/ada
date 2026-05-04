# Engine YAML Rule Authoring Guide

Language: [Chinese](RULE_GUIDE_CN.md)

This guide explains how to author, validate, and troubleshoot YAML detection rules for the ADAegis engine module. Engine rules have two layers:

- Sigma single-event rules turn one raw winlog or pktlog record into an activity.
- Flow correlation rules turn one or more activities into a threat event by using time windows, field relations, counters, Redis cache sets, and LDAP-backed context.

The recommended workflow is to write and validate Sigma rules first, then write Flow rules that reference the Sigma rule `id` values. Flow rules do not match raw logs directly.

## Rule Directories

Development and runtime locations:

| Rule type | Repository directory | Runtime directory | Purpose |
| --- | --- | --- | --- |
| winlog Sigma | `engine/rules/winlog` | `/home/adadmin/rules/winlog` | Windows eventlog single-event detection. |
| pktlog Sigma | `engine/rules/pktlog` | `/home/adadmin/rules/pktlog` | Packet, protocol, or traffic single-event detection. |
| Flow | `engine/rules/flow` | `/home/adadmin/rules/flow` | Multi-event, count, and mixed winlog plus pktlog correlation. |

Engine loads `.yml` files from the runtime directories on startup. After changing rules, trigger a hot reload or restart engine.

```shell
redis-cli PUBLISH ada:engine:reload reload
```

Sending `SIGHUP` to the engine process also reloads rules. Reload refreshes Flow rules, winlog Sigma rules, pktlog Sigma rules, and Redis field maps used by Flow correlation.

## Naming and ID Conventions

Recommended IDs and filenames:

| Type | ID example | Filename example | Constraint |
| --- | --- | --- | --- |
| winlog Sigma | `winlog-0104-0001` | `0104-0001-sensitive_login_succ.yml` | `multi_eve` Flow rules can only reference `winlog-*`. |
| pktlog Sigma | `pktlog-0200-0001` | `0200-0001-ldap_bind.yml` | `multi_pkt` Flow rules can only reference `pktlog-*`. |
| Flow | `flow-0005` | `0005-sensitive_user_login.yml` | Flow IDs must be unique. Duplicate IDs are skipped. |

Rule loading validates these constraints:

- `tags` must contain at least one item.
- `level` must be one of `info`, `low`, `medium`, `high`, `critical`, or a number from `1` to `5`.
- Flow `event_type` must be `count`, `multi_eve`, `multi_pkt`, or `multi_eve_pkt`.
- Flow `sigma_rules` can contain at most 16 Sigma IDs.
- Flow `win_size` must be parseable and cannot exceed 6 hours.
- `$sN` references in Flow `match_by` cannot exceed the number of configured `sigma_rules`.

## Sigma Single-Event Rules

Sigma rules match one raw event and produce an activity. winlog and pktlog rules share the same YAML structure. The main differences are the rule ID prefix, directory, and event fields.

### Base Template

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

### Sigma Top-Level Fields

| Field | Required | Description |
| --- | --- | --- |
| `title` | Recommended | Activity title shown to users. |
| `id` | Yes | Unique rule ID. Use `winlog-*` for winlog and `pktlog-*` for pktlog. |
| `status` | Recommended | Rule state, such as `experimental`, `test`, or `stable`. |
| `description` | Recommended | Activity description and context. |
| `references` | No | Reference URL list. |
| `author` | No | Rule author. |
| `date` | No | Creation date. |
| `modified` | No | Last modified date. |
| `tags` | Yes | At least one tag. `tags[0]` is used as the primary ATT&CK or rule category tag. |
| `logsource` | Yes | Source metadata. Existing built-in rules usually use `winlog` or `pktlog`. |
| `detection` | Yes | Sigma matching logic. Must contain `condition`. |
| `fields` | Recommended | Raw event fields extracted into the activity. Flow-dependent fields must be available here. |
| `unique_fields` | Recommended | Fields used to build activity `unique_id`. Legacy Flow instance grouping uses this when `cache_key` is absent. |
| `rdx_key` | No | Built-in context cache key. Mainly used to provide Redis set context for later rules. |
| `level` | Yes | Risk level. Numeric `1..5` is converted to `info..critical`. |

### `logsource`

Engine supports scalar and mapping forms.

Scalar form:

```yaml
logsource: winlog
```

Mapping form:

```yaml
logsource:
  product: windows
  category: process_creation
  service: security
  definition: "optional text"
```

Most built-in rules use the scalar form. New rules should usually use `winlog` or `pktlog` so they stay consistent with directory and ID prefix conventions.

### `detection`

`detection` contains named selection, filter, or keyword blocks plus one `condition`.

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

The block name itself does not enforce positive or negative behavior. The `condition` expression decides that. Local convention:

- Use `selection_*` for positive match criteria.
- Use `filter_*` for false-positive exclusions.
- Use `keyword*` for keyword matching.

### Exact Field Matching

```yaml
detection:
  selection:
    EventID: 4624
    TargetUserName: administrator
  condition: selection
```

String values are exact matches by default. Numeric rule values are supported, and event values can be JSON numbers, integers, or numeric strings.

```yaml
detection:
  selection:
    EventID: 4624
    LogonType: 3
  condition: selection
```

Selection values currently support strings, integers, string lists, and integer lists. Do not use boolean selection values or mixed-type lists.

### String Modifiers

Field names can use `|` modifiers.

| Modifier | Example | Meaning |
| --- | --- | --- |
| `contains` | `CommandLine|contains: mimikatz` | Field contains the given string. |
| `startswith` | `Image|startswith: C:\Windows\` | Field starts with the given prefix. |
| `endswith` | `TargetUserName|endswith: "$"` | Field ends with the given suffix. |
| `re` | `CommandLine|re: "(?i)sekurlsa"` | Regular expression match. |
| `all` | `CommandLine|contains|all: [...]` | Every list item must match. |

Example:

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

If multiple mutually exclusive string modifiers are used on the same field, the last one wins. Avoid combining `contains`, `startswith`, `endswith`, and `re` on the same key.

### List Matching

String lists are OR by default.

```yaml
detection:
  selection:
    AuthenticationPackageName:
      - NTLM
      - Kerberos
  condition: selection
```

Integer lists are also OR by default.

```yaml
detection:
  selection:
    EventID:
      - 4624
      - 4625
  condition: selection
```

Do not mix strings and numbers in the same list.

### Wildcards and Regex

String values can use `*` wildcards.

```yaml
detection:
  selection:
    CommandLine: "*powershell*EncodedCommand*"
  condition: selection
```

Regular expression modifier:

```yaml
detection:
  selection:
    CommandLine|re: "(?i)(mimikatz|sekurlsa)"
  condition: selection
```

Slash-wrapped strings can also be treated as regex patterns. For readability, prefer `|re` in new rules.

### `condition` Expressions

`condition` supports:

- `and`
- `or`
- `not`
- Parentheses
- `1 of selection*`
- `all of selection*`
- `1 of them`
- `all of them`

Example:

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

Wildcard selection:

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

Parenthesized expression:

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

### Selection Lists

A selection can be a list of maps. The maps are OR branches.

```yaml
detection:
  selection:
    - EventID: 4624
      LogonType: 3
    - EventID: 4648
      ProcessName|endswith: "\\runas.exe"
  condition: selection
```

This matches if either map matches.

### Keyword Rules

A detection item whose name starts with `keyword` is parsed as a keyword rule. The underlying event type must provide keyword text through `Keywords()`.

```yaml
detection:
  keywords:
    - mimikatz
    - sekurlsa
  condition: keywords
```

Keyword lists only support strings and are matched as contains-style text patterns.

### Legacy `key/value` Shape

Engine keeps compatibility for historical test rules that use a `key/value` detection shape. Do not author new rules in this form.

Legacy shape:

```yaml
detection:
  selection:
    - key: EventID
      value: 4624
  condition: selection
```

Preferred shape:

```yaml
detection:
  selection:
    EventID: 4624
  condition: selection
```

### `fields`

`fields` controls which raw event fields are copied into the activity. Flow `match_by`, `cache_key`, and `unique_filter` depend on activity fields.

```yaml
fields:
  - Hostname
  - TargetDomainName
  - TargetUserName
  - IpAddress
```

Flow loading merges fields referenced by `match_by` and `cache_key` into the related Sigma field set, but rule authors should still write the important fields explicitly for review and debugging.

### `unique_fields`

`unique_fields` builds the Sigma activity `unique_id`. If a Flow rule does not configure `detection.cache_key`, the legacy Flow instance key falls back to this `unique_id`.

```yaml
unique_fields:
  - Hostname
  - TargetUserName
  - IpAddress
```

Guidelines:

- For single-event alerts, choose fields that describe the same behavior entity.
- For mixed-source Flow correlation, prefer Flow `cache_key` instead of relying on each Sigma rule's own `unique_id`.
- Empty fields reduce grouping quality. Mock logs must cover all key fields.

### `rdx_key`

`rdx_key` is a built-in context cache hook. It is mainly used to write selected activity data into Redis sets that later rules can query.

```yaml
rdx_key: rule_cache:aduser_info
```

Notes:

- This is an internal convention, not a generic key-value DSL.
- New correlation rules should use Flow `cache_key` for instance grouping and `$v.cache` or `$v.ldap` for context set checks.
- Do not add arbitrary `rdx_key` values unless the code consumes them.

## Flow Correlation Rules

Flow rules correlate Sigma activities into threat events. A Flow rule does not match raw logs.

### Base Template

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

### Flow Top-Level Fields

| Field | Required | Description |
| --- | --- | --- |
| `title` | Recommended | Threat event title. |
| `id` | Yes | Unique Flow ID. Duplicate IDs are skipped. |
| `status` | Recommended | Rule state. |
| `enable` | No | Defaults to enabled. Set `enable: false` to disable. |
| `description` | Recommended | Threat event description. |
| `references` | No | Reference URLs. |
| `author` | No | Author. |
| `date` | No | Creation date. |
| `modified` | No | Last modified date. |
| `tags` | Yes | At least one tag. |
| `logsource` | Yes | Must be `flow`. |
| `detection` | Yes | Flow correlation definition. |
| `unique_filter` | No | Threat event deduplication. |
| `level` | Yes | Risk level. |

### `event_type`

| Type | Sigma reference requirement | Use case |
| --- | --- | --- |
| `count` | Usually one Sigma rule. `$sN` can still specify the counted rule. | Repeated behavior inside a time window, such as brute force. |
| `multi_eve` | Only `winlog-*` Sigma rules. | Correlate multiple Windows eventlog activities. |
| `multi_pkt` | Only `pktlog-*` Sigma rules. | Correlate multiple packet or protocol activities. |
| `multi_eve_pkt` | Must include both `winlog-*` and `pktlog-*`. | Mixed winlog plus pktlog correlation. |

If `event_type` and Sigma ID prefixes do not match, the Flow rule is skipped during loading.

### `sigma_rules` and `$sN`

The order of `sigma_rules` defines `$sN` selectors in `match_by`.

```yaml
detection:
  sigma_rules:
    - winlog-0000-0001  # $s1
    - winlog-0102-0001  # $s2
  match_by: "$s1.TargetUserName == $s2.SubjectUserName AND $s1.Hostname == $s2.Hostname"
```

Rules:

- `$s1` maps to `sigma_rules[0]`.
- `$s2` maps to `sigma_rules[1]`.
- Up to `$s16` is supported.
- Field names must match activity field names.
- Referencing a non-existent `$sN` makes the Flow rule invalid.

### `win_size`

`win_size` is the Flow time window.

```yaml
detection:
  win_size: 30s
```

Common units:

- `s` seconds
- `m` minutes
- `h` hours

The maximum window is 6 hours. Larger windows keep more activity in Redis and cost more to scan. Start with `30s`, `60s`, or `5m` unless the behavior clearly spans longer periods.

### `sorted`

```yaml
detection:
  sorted: false
```

`sorted` controls whether activity order must follow `sigma_rules`.

- `false`: order is not enforced. This is appropriate for most correlation rules.
- `true`: events must appear in the same order as `sigma_rules`. Use it for stage-based behavior chains.

The default is `false`.

### `match_by` Relation Expressions

Flow `match_by` supports field relations, set membership, count expressions, and boolean combinations.

Field relation:

```yaml
match_by: "$s1.TargetUserName == $s2.SubjectUserName"
```

Supported operators:

| Operator | Meaning |
| --- | --- |
| `==` | String or numeric equality. |
| `!=` | Inequality. |
| `>` | Greater than. |
| `>=` | Greater than or equal. |
| `<` | Less than. |
| `<=` | Less than or equal. |
| `in` | Left value is in the right-side set. |

Constant comparison:

```yaml
match_by: "$s1.LogonType == 3"
```

Flow condition parsing removes spaces. Constants should not contain spaces. If the rule needs complex text matching, do it in the Sigma layer and let Flow compare extracted fields.

### `match_by` Boolean Expressions

Flow `match_by` uses an AST parser.

```yaml
match_by: "($s1.UserName == $s2.TargetUserName OR $s1.UserSid == $s2.TargetUserSid) AND NOT ($s1.TargetDomainName == blocked)"
```

Rules:

- `AND`, `OR`, and `NOT` are case-insensitive.
- Parentheses are supported.
- Default precedence is `NOT > AND > OR`.
- Parentheses inside `$v.cache.key_...(...)` and `$v.ldap.key_...(...)` belong to key templates and are not treated as boolean grouping.

Use explicit parentheses in complex rules to make review easier.

### `count` Rules

`event_type: count` uses a count expression.

Total activity count:

```yaml
detection:
  event_type: count
  win_size: 30s
  sigma_rules:
    - winlog-0101-0002
  match_by: "$s1._count >= 5"
```

Equivalent form:

```yaml
match_by: "len($s1) >= 5"
```

Non-empty field occurrence count:

```yaml
match_by: "len($s1.TargetUserName) >= 5"
```

Distinct field count:

```yaml
match_by: "len(distinct($s1.TargetUserName)) >= 3"
```

Compatible field-level count form:

```yaml
match_by: "$s1.TargetUserName._count >= 3"
```

All count forms support:

- `==`
- `!=`
- `>`
- `>=`
- `<`
- `<=`

Distinct counting uses `trim + lower`. This is suitable for password spraying, account enumeration, one source targeting many users, and similar patterns.

### `$v.slice` Static Sets

`$v.slice` uses a JSON string array as a static set.

```yaml
match_by: "$s1.LogonType in $v.slice.[\"3\",\"10\"]"
```

Notes:

- The right side must be a JSON string array.
- Parsing removes spaces, so do not depend on spaces inside values.
- Use `$v.cache` or `$v.ldap` when the set changes over time.

### `$v.cache` Redis Sets

`$v.cache` checks membership in a Redis set.

```yaml
match_by: "$s1.TargetUserName in $v.cache.key_ada:engine:%s:sensitive_users($s1.TargetDomainName)"
```

Syntax:

```text
$sN.Field in $v.cache.key_<redis-key-template>(<param-list>)
```

Rules:

- The template must start with `key_`.
- The text after `key_` is the real Redis key template.
- Each `%s` placeholder must have one parameter.
- Parameters must be `$sN.Field` references.
- Parameter values are normalized with `trim + lower`.
- When the parameter field is `TargetDomainName`, engine can use `Hostname` to normalize NetBIOS names into FQDN-style domains.

Example:

```yaml
match_by: "$s1.TargetUserName in $v.cache.key_ada:engine:%s:honeypot_accounts($s1.TargetDomainName)"
```

Corresponding Redis set:

```shell
redis-cli SADD ada:engine:example.com:honeypot_accounts fake_admin
```

Fixed key without parameters:

```yaml
match_by: "$s1.TargetUserName in $v.cache.key_ada:engine:global:vip_users"
```

### `$v.ldap` Async LDAP Sets

`$v.ldap` uses the same syntax as `$v.cache`, but a cache miss triggers an asynchronous LDAP lookup through tasker.

```yaml
match_by: "$s1.TargetUserName in $v.ldap.key_ada:engine:%s:sensitive_users($s1.TargetDomainName)"
```

Runtime behavior:

1. FlowMatcher builds the Redis set key from the template.
2. FlowMatcher runs `SMEMBERS`.
3. If the set exists and contains the left-side value, matching succeeds synchronously.
4. If the set is missing or empty, engine writes `ada:engine:ldap_search_pending:<hash>` with a 60 second TTL.
5. Engine publishes a lookup request to `ada:engine:ldap_search_channel`.
6. tasker reads the domain LDAP account, queries LDAP asynchronously, and writes results back to the Redis set with a 60 second TTL.
7. The current FlowMatcher cycle does not wait for LDAP. A later cycle uses the refilled Redis set.

Supported LDAP-backed sets:

| Redis key shape | Lookup content |
| --- | --- |
| `ada:engine:<domain>:sensitive_users` | Sensitive users, for example `adminCount=1` users. |
| `ada:engine:<domain>:sensitive_groups` | Built-in sensitive groups. |
| `ada:engine:<domain>:sensitive_computers` | DC, RODC, and other sensitive computers. |

Sets that are not automatically queried through LDAP:

| Redis key shape | Recommendation |
| --- | --- |
| `ada:engine:<domain>:honeypot_accounts` | Use `$v.cache`; populate the set manually or through an external sync job. |

Development guidance:

- The first `$v.ldap` miss usually requires another FlowMatcher cycle before it can alert.
- To validate expression logic quickly, prefill the Redis set with `SADD`, then clear it to test miss and refill behavior.
- Do not put LDAP lookups in Sigma rules. LDAP context belongs in Flow.

### `cache_key` Flow Instance Grouping

`detection.cache_key` decides which Flow instance receives a matched Sigma activity. It is the key setting for mixed winlog plus pktlog correlation.

Without `cache_key`, engine uses the Sigma activity `unique_id`. Different Sigma rules often produce different `unique_id` values, so cross-source activities may not enter the same instance.

Example:

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

Field spec:

```text
<field>|<normalizer>|<normalizer>
```

Supported normalizers:

| Normalizer | Meaning |
| --- | --- |
| `trim` | Remove leading and trailing whitespace. |
| `lower` | Convert to lowercase. |
| `domain` | Normalize domains. For example, combine `EXAMPLE` with `dc01.example.com` to get `example.com`. |
| `ip` | Normalize IP strings through an IP parser. |

Rules:

- `cache_key` map keys must be Sigma IDs listed in `sigma_rules`.
- Each Sigma ID must have at least one field spec.
- If a field is empty, the activity is not written to that Flow instance.
- Different Sigma rules do not have to use the same field names, but their field values should describe the same entity.
- Fields referenced in `cache_key` are automatically added to the related Sigma extraction field set.

Recommendations:

- `multi_eve_pkt` should almost always define `cache_key`.
- User grouping should usually use `domain + username`.
- Host grouping should usually use `hostname` or `domain + computer`.
- Network grouping should use the `ip` normalizer.
- Do not use high-cardinality or random fields, such as process ID, ephemeral port, or Mongo ID.

### `unique_filter` Threat Event Deduplication

`unique_filter` prevents repeated Flow matches from creating duplicate threat events.

```yaml
unique_filter:
  - $s1.TargetDomainName
  - $s1.TargetUserName
  - $s1.IpAddress
  - ttl_3600
```

Rules:

- Field references must use `$sN.Field`.
- `ttl_N` sets the deduplication key TTL in seconds.
- `ttl_0` means no expiration. Use it carefully.
- Deduplication uses fields from the actual matched activity combination.

Recommendations:

- In live environments, prefer a positive TTL such as `ttl_300` or `ttl_3600`.
- Choose the smallest stable field set that represents one security event.
- Do not include timestamps, random IDs, or Mongo IDs.

## Scenario Examples

### 1. Single winlog Activity

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

Use this pattern to validate single-event field extraction.

### 2. Single pktlog Activity

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

pktlog fields must match the current sensor output. Do not use fields that are not emitted by the sensor.

### 3. Failed Login Brute Force

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

To detect one IP trying many accounts:

```yaml
match_by: "len(distinct($s1.TargetUserName)) >= 5"
```

### 4. Multiple winlog Activities

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

### 5. Multiple pktlog Activities

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

### 6. Mixed winlog plus pktlog Correlation

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

This is the recommended pattern for the `multi_pkt_winlog` requirement. Use `event_type: multi_eve_pkt` and define `cache_key` so different sources enter the same Flow instance.

### 7. LDAP Sensitive User Check

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

The first miss triggers async LDAP lookup. To validate matching immediately, prefill Redis:

```shell
redis-cli SADD ada:engine:example.com:sensitive_users administrator
redis-cli EXPIRE ada:engine:example.com:sensitive_users 60
```

### 8. Honeypot Account Check

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

Honeypot accounts are not automatically queried through LDAP. Populate them manually or with an external sync task.

## Mock Logs and End-to-End Validation

### Send Mock Logs to the Receiver

The server receives syslog records and writes JSON payloads into Redis queues. A UDP syslog payload can be used in test environments.

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

Use the actual test server receiver port from configuration. pktlog works the same way, but the JSON fields must match pktlog rules.

### Write Directly to Redis Queues

For local or test debugging, write directly to Redis queues to isolate engine behavior.

```shell
redis-cli LPUSH ada:evelog_queue '{"@timestamp":1714800000000,"Hostname":"dc01.example.com","EventID":4624,"LogonType":3,"AuthenticationPackageName":"NTLM","TargetDomainName":"EXAMPLE","TargetUserName":"administrator","TargetUserSid":"S-1-5-21-1-2-3-500","IpAddress":"192.168.7.5"}'
```

pktlog queue:

```shell
redis-cli LPUSH ada:pktlog_queue '{"@timestamp":1714800000000,"Hostname":"dc01.example.com","Protocol":"ldap","Action":"bind","AuthType":"simple","Domain":"EXAMPLE","UserName":"administrator","SrcIp":"192.168.7.5","DstIp":"192.168.7.2","DstPort":389}'
```

### Validate Activity

MongoDB:

```shell
mongosh db_ada --eval 'db.tb_alert_activity.find().sort({_id:-1}).limit(5).pretty()'
```

Elasticsearch:

```shell
curl -s 'http://127.0.0.1:9200/ada-activity/_search?size=5&sort=@timestamp:desc'
```

### Validate Flow Instances

Flow mapping:

```shell
redis-cli HGETALL ada:engine:flow_rule_map
```

Active instances:

```shell
redis-cli SMEMBERS ada:engine:active:flow-1004
```

Instance members:

```shell
redis-cli ZRANGE 'ada:engine:instance:flow-1004_<instance_key>' 0 -1 WITHSCORES
```

### Validate Threat Events

```shell
mongosh db_ada --eval 'db.tb_alert_event.find().sort({_id:-1}).limit(5).pretty()'
```

Notification queue:

```shell
redis-cli LRANGE ada:server:notify_queue 0 5
```

### Validate `$v.ldap`

Clear cache first:

```shell
redis-cli DEL ada:engine:example.com:sensitive_users
```

Trigger the rule, then check pending keys:

```shell
redis-cli --scan --pattern 'ada:engine:ldap_search_pending:*'
```

Check async refill:

```shell
redis-cli SMEMBERS ada:engine:example.com:sensitive_users
redis-cli TTL ada:engine:example.com:sensitive_users
```

If refill does not happen, inspect tasker logs for LDAP account lookup, bind, search, and Redis write-back failures.

## Troubleshooting

### Rule Is Not Loaded

Check:

- File extension is `.yml`.
- `tags` is not empty.
- `level` is valid.
- Flow `logsource` is `flow`.
- Flow `event_type` is valid.
- Flow `win_size` does not exceed 6 hours.
- Flow `match_by` does not reference missing `$sN`.
- `cache_key` only references Sigma IDs listed in `sigma_rules`.

### Sigma Does Not Match

Check:

- Raw event field names exactly match rule field names.
- Numeric fields can be converted to integers.
- Selection lists do not mix strings and numbers.
- The rule does not use unsupported boolean selection values.
- `condition` does not accidentally make a filter positive.
- pktlog field names match the current sensor output.

### Flow Does Not Generate Threat Events

Check:

- Sigma activity is generated first.
- `ada:engine:flow_rule_map` maps the Sigma ID to the Flow ID.
- Activity is written to `ada:engine:instance:<flow_id>_<instance_key>`.
- `cache_key` fields are not empty.
- Fields used by `match_by` exist in the activity.
- `unique_filter` is not suppressing duplicates.
- `win_size` is not too short.
- `sorted: true` is not rejecting the event order.

### `multi_eve_pkt` Does Not Match

Start with `cache_key`:

- Can winlog and pktlog normalize to the same user, host, IP, or domain?
- Is one side using NetBIOS domain and the other using FQDN? Use `domain`.
- Is username casing inconsistent? Use `lower|trim`.
- Is IP formatting inconsistent? Use `ip`.
- Did the rule include unstable fields such as ephemeral ports or process IDs in `cache_key`?

### `$v.cache` Does Not Match

Check:

- The Redis key generated by the template is the key you expect.
- The Redis set element matches the normalized left-side value.
- The number of `%s` placeholders equals the number of parameters.
- Template parameter fields are not empty.
- `TargetDomainName` plus `Hostname` normalizes to the expected domain.

### `$v.ldap` Does Not Match

Check:

- Whether the Redis set already exists. Empty sets still trigger miss behavior.
- Whether `ada:engine:ldap_search_pending:<hash>` is suppressing repeated lookups for 60 seconds.
- Whether tasker is running and subscribed to `ada:engine:ldap_search_channel`.
- Whether the domain LDAP account exists in Redis.
- Whether the domain controller is reachable.
- Whether the set type is supported: `sensitive_users`, `sensitive_groups`, or `sensitive_computers`.

### ES Has No Activity Documents

MongoDB and Elasticsearch writes are separate paths after Sigma match. ES bulk writer can have a short delay.

Check:

- MongoDB `tb_alert_activity` contains the record.
- Engine logs show ES bulk retry or dropped batch errors.
- ES index `ada-activity` exists.
- ES service is reachable.

## Rule Development Checklist

Before shipping a rule, verify:

- Rule ID is unique and prefix matches the directory and type.
- `tags` is non-empty and `level` is valid.
- Sigma `condition` includes positive selections and false-positive filters.
- Sigma `fields` includes display fields, Flow fields, and `unique_fields`.
- Flow `event_type` matches Sigma ID prefixes.
- Flow `sigma_rules` order matches `$sN` usage.
- Flow `win_size` matches the behavior time span.
- `multi_eve_pkt` defines `cache_key`.
- `cache_key` uses necessary normalizers.
- `$v.cache` and `$v.ldap` key templates produce real Redis keys.
- `unique_filter` uses stable fields and a reasonable TTL.
- Mock logs produce Sigma activity.
- Mock logs produce Flow threat event.
- `$v.cache` is validated with a populated Redis set.
- `$v.ldap` is validated for miss, async lookup, refill, and later match.

## Recommended Development Workflow

1. Define the detection scenario and required raw fields.
2. Write the winlog or pktlog Sigma rule first.
3. Use mock logs to verify `tb_alert_activity` and extracted `fields`.
4. If single-event alerting is enough, proceed to review.
5. If correlation is required, write a Flow rule and choose `event_type`.
6. Configure `cache_key` for `multi_eve_pkt` or any rule where correlated fields differ by source.
7. Trigger each Sigma activity with minimal mock data.
8. Confirm related activities enter the same Redis Flow instance.
9. Confirm `match_by` succeeds and creates `tb_alert_event`.
10. Add `unique_filter` and verify repeated logs do not create noisy duplicate events.
11. Trigger hot reload and run an end-to-end test in the test environment.
12. Record the test rule, mock data, and expected result in the change notes.
