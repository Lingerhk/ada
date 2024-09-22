


### 


### mongodb修复(因断电导致)
```shell
#root执行：
mongod --repair --dbpath /var/lib/mongodb

#修改权限
chown -R mongodb:mongodb /var/lib/mongodb/*

#启动mongod
systemctl start mongod
```

### mongodb备份
```shell
#backup
mongodump -u user_ada --db db_ada --gzip --archive > db_ada_`date "+%Y-%m-%d"`.gz

#unzip
gunzip db_backup.gz

#import
mongorestore --archive=db_ada --gzip --db db_ada -u user_ada
```

### Elasticsearch下载
```shell
#下载
https://www.elastic.co/cn/downloads/past-releases/elasticsearch-7-17-16

https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.17.16-x86_64.rpm
```