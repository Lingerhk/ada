# Adaegis Sensor（Windows）调试/发布/自升级 备忘

> 目的：把这次排障（DC 上 Adaegis 服务 1053 启动失败）以及后续“通过 Redis 自升级链路验证”的关键步骤、坑点和常用命令整理下来，方便以后复用。

## 0. 现场信息（这次环境）

- Windows 目标：`192.168.1.10`（域控 DC）
- 中转/测试服务器：`192.168.7.2`（双网卡）
  - `ens18 = 192.168.7.2/24`
  - `ens19 = 192.168.1.2/24`（与 DC 同网段）
- Windows 服务：
  - ServiceName：`adaegis`
  - Binary：`C:\Program Files\adaegis\adaegis.exe`
  - StartName：`LocalSystem`
  - Log：`C:\Program Files\adaegis\logs\sensor.log`

## 1) 典型故障：服务启动 1053 / EventID 7000/7009

### 1.1 现象
- Windows 服务启动失败：
  - `StartService FAILED 1053`
  - System Event：`7000/7009`
- 常见原因：
  1) 启动阶段 panic/异常退出（服务控制管理器等待超时）
  2) 启动阻塞太久（初始化/网络/自升级导致超时）

### 1.2 快速定位手段（**最关键**）
直接在目标机上手工运行 exe，捕获 stderr：

```powershell
cd "C:\Program Files\adaegis"
.\adaegis.exe -m 192.168.1.2
```

- 注意：一定要 `cd` 到程序目录再跑。
  - 否则相对路径会写到 `C:\Windows\System32\sensor.cfg`，导致“你以为改了配置，其实没改对文件”。

这次捕获到的真实根因：

```
panic: failed to decrypt config: cipher: message authentication failed
```

## 2) sensor.cfg 加密方式：只保留 AES-GCM（不再兼容旧格式）

### 2.1 根因解释
- 历史版本从旧加密（legacy，实际为 AES-ECB + zero padding）切到新加密（AES-GCM）。
- DC 上仍是旧格式 `sensor.cfg`，新版本启动阶段解密失败直接 panic → 服务 1053。

### 2.2 正确的“最终形态”流程
> 要求：**不兼容旧加密方式**。

正确做法不是在新版本里长期保留 legacy 解密，而是：

1. 先用能跑起来的版本（或临时兼容版本）在目标机上把 `sensor.cfg` 旋转为 AES-GCM。
2. 然后发布“仅支持 AES-GCM”的最终版本。

#### 配置旋转（关键点）
```powershell
# 1) 停服务
Stop-Service adaegis

# 2) 在正确工作目录运行（确保写的是 C:\Program Files\adaegis\sensor.cfg）
cd "C:\Program Files\adaegis"
.\adaegis.exe -m 192.168.1.2

# 3) 验证 sensor.cfg 变更
Get-Item "C:\Program Files\adaegis\sensor.cfg" | Select Length,LastWriteTime
```

- 这次旋转后典型变化：`sensor.cfg` 长度会变化（例如 `344 -> 396` / 或按不同 yaml 输出有所差异）。

## 3) Redis 自升级链路（必须做到“GET latest_*”）

### 3.1 Redis key（三件套）
在 `agent/sensor/common/const.go` 定义，关键是：

- `ada:sensor:latest_version`：版本号（字符串）
- `ada:sensor:latest_binsum`：sha256（字符串）
- `ada:sensor:latest_binfile`：二进制内容（bytes）

### 3.2 证明“确实是 sensor 自己拉取升级”
在 Redis 上开 `MONITOR`，能看到来自目标机 IP 的读取：

- `GET ada:sensor:latest_version`
- `GET ada:sensor:latest_binsum`
- `GET ada:sensor:latest_binfile`

这比“WinRM 手工替换 exe”更强：因为它证明升级行为来自 sensor 进程本身。

### 3.3 写入 latest_binfile（容器内 redis-cli 无 python 模块时的办法）
在 `192.168.7.2` 的 `ada_redis` 容器里，使用 `-x` 从 stdin 写入二进制：

```bash
# 例：把 /tmp/adaegis.exe 写入 latest_binfile
docker exec -i ada_redis redis-cli -a <redis_pass> --raw -x SET ada:sensor:latest_binfile < /tmp/adaegis.exe
```

然后写 `latest_version`/`latest_binsum`：

```bash
docker exec ada_redis redis-cli -a <redis_pass> SET ada:sensor:latest_version 2.6.11
docker exec ada_redis redis-cli -a <redis_pass> SET ada:sensor:latest_binsum <sha256>
```

## 4) 自升级落盘 ≠ 运行版本生效（必须重启进程加载新 exe）

- `selfupdate.Apply()` 只会替换磁盘上的 exe。
- 正在运行的进程不会自动变成新版本。

正确做法：
- Apply 成功后 `os.Exit(0)`，让 Windows 服务管理器拉起新进程，加载新 exe。

否则会出现：
- 磁盘已是新 exe，但运行逻辑还在老进程里。

## 5) 启动阶段不要立刻做耗时升级（避免 1053/7009）

- Windows SCM 对服务启动响应有超时。
- 如果启动阶段立刻做网络/升级等阻塞操作，会增加 1053/7009 风险。

实践：
- 把 `u.Once()` 延迟执行（例如启动后 sleep 45s 再跑），保证服务快速进入 RUNNING。

## 6) Redis 订阅注意：必须用 PSUBSCRIBE（ACL 限制）

- 生产/现场 ACL 用户 `ada_sensor` 允许 `+psubscribe`，不允许 `+subscribe`。
- 因此代码里要用 `PSUBSCRIBE`，否则会在生产环境订阅失败。

## 7) 版本比较必须用 semver（避免 2.6.9 / 2.6.10 字典序坑）

现状风险：
- 若用字符串比较：`"2.6.10" < "2.6.9"`（字典序）可能导致错误。

建议：
- 用 semver 解析比较（或按 `major.minor.patch` 拆分成 int 比较）。

## 8) 强验证清单（只读）

### 8.1 机器侧：确认磁盘文件就是升级目标
```powershell
Get-FileHash "C:\Program Files\adaegis\adaegis.exe" -Algorithm SHA256
(Get-Item "C:\Program Files\adaegis\adaegis.exe").LastWriteTime
```
对比：
- `SHA256` 是否等于 `ada:sensor:latest_binsum`

### 8.2 Server/Redis 侧：确认心跳/状态带上新版本
- Redis：`HGETALL ada:sensor:id:<uuid>`
  - `version` 字段应为新版本（如 `2.6.11`）
  - `last_online_tm`/`timestamp` 持续刷新

## 9) 打包 adaegis.zip（本地 + 测试环境）

### 9.1 zip 结构（示例）
- `pkg/adaegis.exe`
- `pkg/sensor.cfg`
- `pkg/vc_redist.x64.exe`
- `pkg/npcap-0.93.exe`
- `pkg/*.zip`（插件包）

### 9.2 注意区分两套配置
- **测试环境 zip**：`sensor.cfg` 通常指向测试 server（例如 `RegHost=192.168.1.2`）
- **本地/默认 zip**：`sensor.cfg` 来自 `agent/sensor/cmd/sensor.yaml`（例如 `RegHost=192.168.18.4`）

避免把测试配置混进本地默认包。

---

## 附：常用 Redis / Docker 命令

```bash
# 列出 sensor 相关 key
docker exec ada_redis redis-cli -a <pass> KEYS 'ada:sensor:*'

# 查看某个 sensor 的状态 hash（version/last_online_tm 等）
docker exec ada_redis redis-cli -a <pass> HGETALL ada:sensor:id:<uuid>

# 监控自升级拉取（强证明）
docker exec ada_redis redis-cli -a <pass> MONITOR
```
