# Test Command-Line Tools

This directory contains standalone executable test programs (package `main`) that can be run independently for manual testing and debugging.

## Files

### test_reload.go
A command-line tool to test the rule reload mechanism.

**Usage:**
```bash
# Build and run
go run test_reload.go

# Or build as binary
go build -o test_reload test_reload.go
./test_reload
```

**What it tests:**
- Adding a new alert rule
- Updating an existing rule
- Deleting a rule
- Verifies that each operation triggers:
  - File write to `/home/adadmin/rules/flow/`
  - Reload signal via Redis Pub/Sub
  - Engine rule reload

**Requirements:**
- gRPC server running at 127.0.0.1:8800
- Valid credentials (uses admin user)

## Parent Directory

The parent directory (`../`) contains unit tests (package `test`) that use the goconvey framework and can be run with `go test`.

**Example:**
```bash
cd ..
go test -v -run TestRuleReloadMechanism
go test -v -run TestDashboardStats
```
