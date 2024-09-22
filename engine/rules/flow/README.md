
### Tags 定义
必须至少有一个tag，且tag[0]为 attCkId

### match_by支持类型:

- 计数`count`
```shell
$s1._count == 3
```

- 关系判断`==`,`!=`,`>`,`<`,`>=`,`<=`
```shell
$s1.SubjectUserName == $s2.UserName AND $s1.SourceProcessId == $s2.ProcessId
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
 $s1.ProcessId == $s2.SourceProcessId AND $s1.LoginType in $v.ldap.key_xxx
```


- TODO: IN操作符`==`--`ldap`
```shell
 $s1.ProcessId == $s2.SourceProcessId AND $s1.LoginType == $v.ldap.key_xxx
```
