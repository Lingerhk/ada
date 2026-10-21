# apiserver gRPC API (`ada.proto`)

The Go code in this directory (`ada.pb.go`, `ada_grpc.pb.go`) is generated and
committed. Regenerate it after editing `ada.proto`:

```bash
# one-time: install buf, protoc-gen-go and protoc-gen-go-grpc into $(go env GOPATH)/bin
make proto_tools

# regenerate backend/apiserver/api/v2 and backend/tasker/api
make gen_proto
```

`buf` bundles its own protobuf compiler, so `protoc` does not need to be
installed. The workspace layout lives in `buf.yaml` at the repository root and
the generator options in `buf.gen.yaml`.

## Field validation

Request validation uses [protovalidate](https://github.com/bufbuild/protovalidate).
Rules are declared on the fields with `(buf.validate.field)`, for example:

```proto
string username = 1 [(buf.validate.field) = {string: {min_len: 1}}];
int32  pageIdx  = 1 [(buf.validate.field) = {int32: {gt: 0}}];
string mobile   = 4 [(buf.validate.field) = {ignore: IGNORE_IF_ZERO_VALUE, string: {pattern: "^1[3-9]\\d{9}$"}}];
```

The rules are enforced for every unary RPC by the `validate()` interceptor in
`backend/apiserver/service/service.go`; a violation is returned to the client as
`codes.InvalidArgument`. `backend/apiserver/api/v2/validate_test.go` checks that
every message compiles under protovalidate, so a typo in a rule fails `go test`.

The option definitions are vendored in `third_party/proto/buf/validate/validate.proto`.
