GO ?= go
BUILD_VERSION=3.1.0
BUILD_TIME=$(shell date "+%F %T")
COMMIT_VERSION=$(shell git log -1 --format="%h")
COMMIT_TIME=$(shell git log -1 --format="%ci" | cut -d' ' -f1,2)

BUILD_BASE_PATH=$(shell pwd)
BUILD_PATH_APISERVER=./backend/apiserver/cmd
BUILD_PATH_TASK_SERVER=./backend/tasker/cmd/server
BUILD_PATH_TASK_WORKER=./backend/tasker/cmd/worker
BUILD_PATH_ENGINE=./engine/cmd
BUILD_PATH_SCANNER=./scanner/cmd
BUILD_PATH_INFRA=ada/infra
# protobuf modules (see buf.yaml); generated code is committed, run `make gen_proto` after editing a .proto
PROTO_MODULES=backend/apiserver/api/v2 backend/tasker/api
BUF ?= buf


.PHONY: all gen_proto proto_tools apiserver task_worker task_server engine scanner clean

all: apiserver task_worker task_server engine scanner

# Install the code generators used by gen_proto into $(GOPATH)/bin.
proto_tools:
	$(GO) install github.com/bufbuild/buf/cmd/buf@latest
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Regenerate *.pb.go / *_grpc.pb.go next to each .proto (no protoc needed, buf has a built-in compiler).
gen_proto:
	@for m in $(PROTO_MODULES); do \
		echo "buf generate $$m"; \
		$(BUF) generate $$m --template buf.gen.yaml -o $$m || exit 1; \
	done
	$(GO) vet ./backend/apiserver/api/... ./backend/tasker/api/...

apiserver:
	$(GO) build -ldflags \
        "-w -s -X '${BUILD_PATH_INFRA}/version.BuildVersion=${BUILD_VERSION}'\
        -X '${BUILD_PATH_INFRA}/version.BuildTime=${BUILD_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.BuildName=ADA@apiserver'\
        -X '${BUILD_PATH_INFRA}/version.CommitTime=${COMMIT_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.CommitVersion=${COMMIT_VERSION}'"\
        -o ${BUILD_BASE_PATH}/bin/apiserver ${BUILD_PATH_APISERVER}/apiserver.go

task_worker:
	$(GO) build -ldflags \
        "-w -s -X '${BUILD_PATH_INFRA}/version.BuildVersion=${BUILD_VERSION}'\
        -X '${BUILD_PATH_INFRA}/version.BuildTime=${BUILD_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.BuildName=ADA@task_worker'\
        -X '${BUILD_PATH_INFRA}/version.CommitTime=${COMMIT_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.CommitVersion=${COMMIT_VERSION}'"\
        -o ${BUILD_BASE_PATH}/bin/task_worker ${BUILD_PATH_TASK_WORKER}

task_server:
	$(GO) build -ldflags \
        "-w -s -X '${BUILD_PATH_INFRA}/version.BuildVersion=${BUILD_VERSION}'\
        -X '${BUILD_PATH_INFRA}/version.BuildTime=${BUILD_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.BuildName=ADA@task_server'\
        -X '${BUILD_PATH_INFRA}/version.CommitTime=${COMMIT_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.CommitVersion=${COMMIT_VERSION}'"\
        -o ${BUILD_BASE_PATH}/bin/task_server ${BUILD_PATH_TASK_SERVER}

engine:
	$(GO) build -ldflags \
        "-w -s -X '${BUILD_PATH_INFRA}/version.BuildVersion=${BUILD_VERSION}'\
        -X '${BUILD_PATH_INFRA}/version.BuildTime=${BUILD_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.BuildName=ADA@engine'\
        -X '${BUILD_PATH_INFRA}/version.CommitTime=${COMMIT_TIME}'\
        -X '${BUILD_PATH_INFRA}/version.CommitVersion=${COMMIT_VERSION}'"\
        -o ${BUILD_BASE_PATH}/bin/engine ${BUILD_PATH_ENGINE}/engine.go

scanner:
	CGO_ENABLED=0 $(GO) build -ldflags \
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
