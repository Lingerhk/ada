
## Future
- heatbeat/stats
- upgrade
- policy/cmd
- self-alive

## Sensor打包发布
1.编译sensor主程序
```shell
make.bat
```
2.创建加密配置
```shell
go build enc_cfg.go
./enc_cfg.exe
```
3.更新package目录
```shell
# 将cp ada_sensor.exe /path/package/
# 将cp sensor.cfg /path/package/
# 其他模块如有更新也需要更新到package目录
C:\Users\admin\ada\agent\package
```
4.执行打包并发布到redis
```shell
go build pkg_sensor.go
./pkg_sensor.exe
```
5.[可选]升级sensor主程序
```shell
# 执行上述步骤[1]
# 修改build_new_version.go 中的NewVersion
# 执行go build build_new_version.go
# 执行 build_new_version.exe
```