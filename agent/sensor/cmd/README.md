
#### ADA Sensor模块

- 启动plugin (nxlog\ntap\frc-firewall)
- 接收下发指令，启动/停止plugin
- 监控DC Server状态
- 监控ADA Sensor（资源占用），



### Windows下Sensor安装器
下载此安装器到DC机器上执行，它回连接ADA平台下载最新的agent程序并安装。

#### 该下载器执行的操作
```shell
1.在ADA Server端动态编译installer.exe(或者安装的时候参数指定srv ip和注册码)

2.下载installer.exe到DC端执行，它会从ADA Redis下载Sensor各组件到本地并安装

3.installer.exe执行Sensot注册逻辑，并check各服务都已正常运行
```


#### nxlog安装
https://docs.nxlog.co/userguide/deploy/windows.html
```shell
Start-Process C:\Windows\System32\msiexec.exe -ArgumentList "/i C:\nxlog-ce-3.2.2329.msi /q INSTALLDIR=" C:\Program Files\ada_sensor\nxlog"" -wait
Restart-Service -Name nxlog

```

#### Windows Debug支持
- 查看进程启动参数
```
# https://superuser.com/questions/1003921/how-to-show-full-command-line-of-all-processes-in-windows
wmic process where "name like '%ntap_remote.exe%'" get processid,commandline
```

#### 代码签名
```shell

# 第三方证书
https://www.ssldun.com/ssl/comodo/cs.htm

# 签名工具
```


#### 安装器GUI
```shell
https://gist.github.com/mattiasghodsian/a30f50568792939e35e93e6bc2084c2a

https://nsis.sourceforge.io/Main_Page
```