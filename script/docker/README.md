

#### docker 安装
https://docs.docker.com/engine/install/ubuntu/



##### Docker build
```shell
docker build -f redis/Dockerfile -t ada_redis:2.9.1 .
docker build --no-cache -f redis/Dockerfile -t ada_redis:2.9.1 .
```

##### Docker run
```shell
docker run -d -p 27017:27017/tcp --name ada_mongodb ada_mongodb:2.9.1
docker run -d -p 6379:6379/tcp -p5513:5513/tcp --name ada_redis ada_redis:2.9.1
docker run -d -p 9200:9200/tcp --env-file .env --name ada_elasticsearch ada_elasticsearch:2.9.1

```

##### Docker rm
如果 Docker 容器正在运行，你在删除它们之前需要先停止运行。
https://colobu.com/2018/05/15/Stop-and-remove-all-docker-containers-and-images/

```shell    
# 停止所有容器运行：
docker stop $(docker ps -a -q)

# 删除所有停止运行的容器：
docker rm $(docker ps -a -q)

# 列出所有无效的卷标
docker volume ls -qf dangling=true

# 删除无效的卷
docker volume rm $(docker volume ls -qf dangling=true)

# 删除所有镜像
docker rmi $(docker images -q)
```




https://github.com/allen-munsch/docker-redis-ssl-example/tree/main/redis

---

## 验证流程：触发 LDAP 查询流量 → pktlog 入 ES → DashboardLogStats

> 目标：用一次可复现的方式验证 **Zeek→Redis→tasker_server→Elasticsearch** 的 pktlog 链路，以及 apiserver 的 **DashboardLogStats** 统计接口。

### 0. 前置
- 确保 `docker compose ps` 里 `ada_zeek / ada_redis / ada_elasticsearch / ada_backend` 均为 Up
- 确保 ES 可访问（宿主机上一般是 `http://127.0.0.1:9200`）

### 1) 在 7.8 触发 LDAP 流量（推荐用 docker 临时容器）
在 `192.168.7.8`（同时有 `192.168.1.8` 这张内网卡）上执行：

```bash
# 触发一次 LDAP 查询流量（示例）
docker run --rm alpine:3.20 sh -c \
  "apk add --no-cache openldap-clients >/dev/null \
  && ldapsearch -H ldap://<DC_IP>:389 -x \
      -D '<DOMAIN\\\USER>' -w '<PASSWORD>' \
      -b 'DC=example,DC=local' '(sAMAccountName=vagrant)' dn | head"
```

### 2) 触发 100 次随机查询（1–3 秒随机间隔，查询条件不完全相同）
> 注意：如果 DC 有账号锁定策略，请换成不会锁的测试账号，或把错误密码比例降为 0。

```bash
cat > /tmp/ldap_burst.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail

DC_IP=<DC_IP>
BASE_DN='DC=example,DC=local'
BIND_DN='<DOMAIN\\USER>'
BIND_PW='<PASSWORD>'

filters=(
  '(sAMAccountName=vagrant)'
  '(sAMAccountName=Administrator)'
  '(sAMAccountName=krbtgt)'
  '(objectClass=user)'
  '(objectClass=computer)'
  '(cn=*)'
  '(|(sAMAccountName=vagrant)(sAMAccountName=krbtgt))'
  '(displayName=*)'
  '(name=*)'
)
attrs=(dn cn sAMAccountName objectClass memberOf whenCreated)
scopes=(sub one)

pick() { local -n a=$1; echo "${a[$((RANDOM % ${#a[@]}))]}"; }

for i in $(seq 1 100); do
  f=$(pick filters)
  a=$(pick attrs)
  s=$(pick scopes)

  # 10%：查询一个随机不存在的用户（让 result_count 有变化）
  if (( RANDOM % 10 == 0 )); then
    f="(sAMAccountName=doesnotexist$RANDOM)"
  fi

  sleep $(( (RANDOM % 3) + 1 ))
  echo "[$(date -u +%H:%M:%S)] $i/100 scope=$s filter=$f attr=$a" >&2

  docker run --rm alpine:3.20 sh -c "apk add --no-cache openldap-clients >/dev/null \
    && ldapsearch -H ldap://$DC_IP:389 -x \
        -D '"'"'$BIND_DN'"'"' -w '"'"'$BIND_PW'"'"' \
        -b '"'"'$BASE_DN'"'"' -s $s '"'"'$f'"'"' $a >/dev/null" || true

done
SH
chmod +x /tmp/ldap_burst.sh
/tmp/ldap_burst.sh
```

### 3) 在 ADA test 环境验证 ES（pktlog index）
在 `192.168.7.2` 上执行：

```bash
# 1) 看当天 index 是否存在、文档数是否增长
curl -u 'elastic:<ES_PASSWORD>' 'http://127.0.0.1:9200/_cat/indices/ada-packetlog-*?v'

# 2) 只看当天 count
curl -u 'elastic:<ES_PASSWORD>' 'http://127.0.0.1:9200/ada-packetlog-$(date -u +%Y.%m.%d)/_count?pretty'

# 3) 抽查 5 条最新（按 ts 降序）
curl -u 'elastic:<ES_PASSWORD>' -H 'Content-Type: application/json' \
  'http://127.0.0.1:9200/ada-packetlog-$(date -u +%Y.%m.%d)/_search?pretty' \
  -d '{"size":5,"sort":[{"ts":"desc"}]}'
```

同时可通过日志确认 tasker_server 正在消费并写 ES：

```bash
docker exec ada_backend sh -lc "grep -n 'PktlogServe\|pktlogSync\|on-failure' /home/adadmin/logs/tasker_server.log | tail -n 50"
```

### 4) 验证 DashboardLogStats（gRPC API）
方式 A（推荐，开发机/有 Go 环境）：
```bash
cd backend/apiserver/test
# 依赖：apiserver gRPC 在 127.0.0.1:8800，且 Redis/ES/Mongo 都可用
go test -v -run TestDashboardLogStats
```

方式 B（如果你有 grpcurl）：
- 需要带 `authorization: Bearer <token>` 的 metadata；token 生成方式可参考：`backend/apiserver/test/main_test.go`（util.GenerateToken）。

> 期望现象：
> - ES 中 `ada-packetlog-YYYY.MM.DD` 文档数明显增长
> - `DashboardLogStats` 返回 `Duration*60+1` 个点，并且 `pktlogCounts` 在最新分钟附近有非 0 值
