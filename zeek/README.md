## Background
```shell
OS: Ubuntu 24.04 LTS
```

## Build Base image
```shell
# 
cd zeek-7.1.0 # entry the source code of zeek:7.1.0
sh update_local.sh # modify the local zeek change into zeek source code.
cd docker && make all # build base image
```

If all run successed, will display the fellow images:
```shell
adadmin@ada:~/zeek/zeek-7.1.0/docker$ docker images
REPOSITORY     TAG       IMAGE ID       CREATED          SIZE
zeek           7.1.0     99fd594644ea   1 hours ago      532MB
zeek           latest    99fd594644ea   1 hours ago      532MB
zeek-build     latest    2081c236d7c4   1 hours ago      958MB
zeek-builder   7.1.0     9e2ddefe2d4d   1 hours ago      743MB
```

## Build Zeek image
```shell
cd plugins
docker build -t ada_zeek:7.1.0 .

# After the docker build done, will have the image:
adadmin@ada:~/zeek/plugins$ docker images
REPOSITORY     TAG       IMAGE ID       CREATED          SIZE
ada_zeek       7.1.0     f9607c616c60   1 hours ago      834MB
```

#### Build local
```shell
# dependencies
sudo apt-get install cmake make gcc g++ flex libfl-dev bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev libkrb5-dev libmaxminddb-dev libhiredis-dev libjemalloc-dev

# build
cd zeek-7.1.0
./configure --enable-jemalloc
make -j8
sudo make install
```