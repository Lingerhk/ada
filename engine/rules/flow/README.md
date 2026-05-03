
### Tags 定义
必须至少有一个tag，且tag[0]为 attCkId

### event_type 支持类型

- `count`: 同窗口同类 activity 计数。
- `multi_eve`: 多条 `winlog-*` activity 关联。
- `multi_pkt`: 多条 `pktlog-*` activity 关联。
- `multi_eve_pkt`: `winlog-*` 与 `pktlog-*` 混合关联。

### cache_key

`cache_key` 用于显式声明不同 Sigma 命中的 activity 如何进入同一个 Flow instance，尤其适合 `multi_eve_pkt` 中字段名不同但语义相同的场景。

```yaml
detection:
  event_type: multi_eve_pkt
  sigma_rules:
    - "winlog-0104-0001"
    - "pktlog-0200-0001"
  cache_key:
    winlog-0104-0001:
      - "TargetDomainName|domain"
      - "TargetUserName|lower|trim"
    pktlog-0200-0001:
      - "Domain|domain"
      - "UserName|lower|trim"
```

支持的 normalizer: `trim`, `lower`, `domain`, `ip`。

### match_by支持类型:

- 计数`count`
```shell
$s1._count >= 3
len($s1) >= 3
len(distinct($s1.TargetUserName)) >= 3
$s1.TargetUserName._count >= 3
```

- 关系判断`==`,`!=`,`>`,`<`,`>=`,`<=`
```shell
$s1.SubjectUserName == $s2.UserName AND $s1.SourceProcessId == $s2.ProcessId
$s1.SubjectUserName == $s2.UserName OR ($s1.SourceProcessId == $s2.ProcessId AND NOT ($s1.LoginType == guest))
```

- IN操作符`in`--`slice`
```shell
 $s1.UserName == $s2.User AND $s1.LoginType in $v.slice.["ss","sd","sc"]
```

- IN操作符`in`--`cache`
```shell
 $s1.ProcessId == $s2.SourceProcessId AND $s1.UserName in $v.cache.key_xxxx
```

- IN操作符`in`--`ldap`
```shell
 $s1.ProcessId == $s2.SourceProcessId AND $s1.LoginType in $v.ldap.key_ada:engine:%s:sensitive_users($s1.TargetDomainName)
```

`$v.ldap` 先同步读取 Redis set；cache miss 时通过 `ada:engine:ldap_search_channel` 触发 tasker 异步 LDAP 查询并回填缓存，避免阻塞 FlowMatcher。
