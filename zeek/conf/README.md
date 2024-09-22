
### 替换zeek配置
```shell
echo "replace zeek conf"
cp conf/node.cfg /usr/local/zeek/etc/node.cfg
cp conf/zeekctl.cfg /usr/local/zeek/etc/zeekctl.cfg
```

### 替换zeek脚本
````shell
echo "replace zeek script"
cp conf/local.zeek /usr/local/zeek/share/zeek/site/local.zeek
cp conf/ascii.zeek /usr/local/zeek/share/zeek/base/frameworks/logging/writers/ascii.zeek
cp conf/init-default.zeek /usr/local/zeek/share/zeek/base/init-default.zeek
cp conf/logging.zeek /usr/local/zeek/share/zeek/base/frameworks/analyzer/logging.zeek
cp conf/files_main.zeek /usr/local/zeek/share/zeek/base/frameworks/files/main.zeek
cp conf/ldap_main.zeek /usr/local/zeek/share/zeek/base/protocols/ldap/main.zeek
```

### 新版zeek7.1.0 配置问题
```
error in /usr/local/zeek/spool/tmp/check-config-zeek/zeekctl-config.zeek, line 14: "redef" used but not previously defined (FileExtract::prefix)
```

- 解决方法：
```
# zeekctl.cfg
# https://github.com/zeek/zeek/blob/b22ec065680a43c6a484416a807f4c3d6a5d9304/NEWS#L131
FileExtractDir =
```