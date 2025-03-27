

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