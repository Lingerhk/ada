
### proto编译说明


#### MacOX下配置
```shell
# update .profile
export GOPATH=/home/adaegis/go
export PATH=$PATH:$GOPATH:/usr/local/go/bin

# install proto,protoc-gen-go
go env -w GO111MODULE=off
go get -u github.com/golang/protobuf/{proto,protoc-gen-go}

# 安装protoc(bin)
https://github.com/protocolbuffers/protobuf/releases/download/v25.1/protoc-25.1-osx-x86_64.zip
unzip protoc-25.1-osx-x86_64.zip
cp bin/protoc $GOPATH/bin/
cp -r include/google $GOPATH/src/

# 安装protoc-gen-govalidators
go get github.com/mwitkow/go-proto-validators/protoc-gen-govalidators
```

#### Linux下配置
```shell

```

#### 生成Proto文件
```shell
cd {ADA-PROJECR}/backend/apiserver/api/v2
# generate:
protoc --govalidators_out=:. --go_out=plugins=grpc:. -I$GOPATH/src:. ada.proto

```
