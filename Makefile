BUILD_VERSION=3.1.0
BUILD_TIME=$(shell date "+%F %T")
COMMIT_VERSION=$(shell git log -1 --format="%h")
COMMIT_TIME=$(shell git log -1 --format="%ci" | cut -d' ' -f1,2)

BUILD_BASE_PATH=$(shell pwd)
BUILD_PATH_APISERVER=backend/apiserver/cmd
BUILD_PATH_TASK=backend/tasker/cmd
BUILD_PATH_RECEIVER=backend/recevier/cmd
BUILD_PATH_ENGINE=engine/cmd
BUILD_PATH_SCANNER=scanner/cmd
BUILD_PATH_INFRA=ada/infra
BUILD_API_PROTO_PATH=${BUILD_BASE_PATH}/backend/apiserver/api/v2
BUILD_RPC_PROTO_PATH=${BUILD_BASE_PATH}/backend/tasker/api


.PHONY: all gen_proto apiserver task_worker task_server engine scanner clean

all: gen_proto apiserver task_worker task_server engine scanner

gen_proto:
	protoc -I=${GOPATH}/src:${BUILD_API_PROTO_PATH} --govalidators_out=:${BUILD_API_PROTO_PATH} --go_out=plugins=grpc:${BUILD_API_PROTO_PATH} ${BUILD_API_PROTO_PATH}/ada.proto
	protoc -I=${BUILD_RPC_PROTO_PATH} --govalidators_out=:${BUILD_RPC_PROTO_PATH} --go_out=plugins=grpc:${BUILD_RPC_PROTO_PATH} ${BUILD_RPC_PROTO_PATH}/ada_task.proto

apiserver: gen_proto
	/usr/local/go/bin/go build -ldflags \
        "-w -s -X '${BUILD_PATH_INFRA}/version.BuildVersion=${BUILD_VERSION}'\
        -X '${BUILD_PATH_INFRA}/version.BuildTime=${BUILD_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.BuildName=ADA@apiserver'\
        -X '${BUILD_PATH_INFRA}/version.CommitTime=${COMMIT_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.CommitVersion=${COMMIT_VERSION}'"\
        -o ${BUILD_BASE_PATH}/bin/apiserver ${BUILD_PATH_APISERVER}/apiserver.go

task_worker:
	/usr/local/go/bin/go build -ldflags \
        "-w -s -X '${BUILD_PATH_INFRA}/version.BuildVersion=${BUILD_VERSION}'\
        -X '${BUILD_PATH_INFRA}/version.BuildTime=${BUILD_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.BuildName=ADA@task_worker'\
        -X '${BUILD_PATH_INFRA}/version.CommitTime=${COMMIT_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.CommitVersion=${COMMIT_VERSION}'"\
        -o ${BUILD_BASE_PATH}/bin/task_worker ${BUILD_PATH_TASK}/worker.go

task_server:
	/usr/local/go/bin/go build -ldflags \
        "-w -s -X '${BUILD_PATH_INFRA}/version.BuildVersion=${BUILD_VERSION}'\
        -X '${BUILD_PATH_INFRA}/version.BuildTime=${BUILD_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.BuildName=ADA@task_server'\
        -X '${BUILD_PATH_INFRA}/version.CommitTime=${COMMIT_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.CommitVersion=${COMMIT_VERSION}'"\
        -o ${BUILD_BASE_PATH}/bin/task_server ${BUILD_PATH_TASK}/server.go

engine:
	/usr/local/go/bin/go build -ldflags \
        "-w -s -X '${BUILD_PATH_INFRA}/version.BuildVersion=${BUILD_VERSION}'\
        -X '${BUILD_PATH_INFRA}/version.BuildTime=${BUILD_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.BuildName=ADA@engine'\
        -X '${BUILD_PATH_INFRA}/version.CommitTime=${COMMIT_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.CommitVersion=${COMMIT_VERSION}'"\
        -o ${BUILD_BASE_PATH}/bin/engine ${BUILD_PATH_ENGINE}/engine.go

scanner:
	/usr/local/go/bin/go build -ldflags \
        "-w -s -X '${BUILD_PATH_INFRA}/version.BuildVersion=${BUILD_VERSION}'\
        -X '${BUILD_PATH_INFRA}/version.BuildTime=${BUILD_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.BuildName=ADA@scanner'\
        -X '${BUILD_PATH_INFRA}/version.CommitTime=${COMMIT_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.CommitVersion=${COMMIT_VERSION}'"\
        -o ${BUILD_BASE_PATH}/bin/scanner ${BUILD_PATH_SCANNER}/scanner.go

clean:
	rm -rf ${BUILD_BASE_PATH}/bin/apiserver
	rm -rf ${BUILD_BASE_PATH}/bin/task_server
	rm -rf ${BUILD_BASE_PATH}/bin/task_worker
	rm -rf ${BUILD_BASE_PATH}/bin/engine
	rm -rf ${BUILD_BASE_PATH}/bin/scanner
