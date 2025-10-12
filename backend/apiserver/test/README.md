# Test Cases

## Directory Structure

```
test/
├── README.md                    # This file
├── main_test.go                 # Test setup and initialization
├── dashboard_test.go            # Dashboard API tests
├── reload_test.go               # Rule reload mechanism tests
├── domain_test.go               # Domain management tests
├── rule_test.go                 # Rule management tests
├── threat_test.go               # Threat detection tests
├── scanrisk_test.go             # Scan/risk assessment tests
├── user_test.go                 # User management tests
├── system_test.go               # System configuration tests
├── sensor_test.go               # Sensor management tests
├── report_test.go               # Report generation tests
├── notify_test.go               # Notification tests
└── cmd/                         # Standalone test executables (package main)
    ├── README.md                # Command-line tools documentation
    └── test_reload.go           # Standalone reload test tool
```

## Running Tests

All test files (except `cmd/`) are part of the `test` package and use the goconvey framework.

**Prerequisites:**
- gRPC server must be running at `127.0.0.1:8800`
- Valid test environment with MongoDB, Redis, Elasticsearch

**Run all tests:**
```bash
cd $ada/backend/apiserver/test
go test -v
```

**Run specific test:**
```bash
# Dashboard API tests
go test -v -run TestDashboardStats
go test -v -run TestDashboardLogStats

# Rule reload mechanism test
go test -v -run TestRuleReloadMechanism

# Domain management tests
go test -v -run TestDomain

# Other tests
go test -v -run TestEncryptPassword
```

## Test Coverage

- **Dashboard API** (`dashboard_test.go`):
  - `TestDashboardStats`: Tests dashboard statistics API (asset counts, alert counts by level, baseline, leak, weakpwd)
  - `TestDashboardLogStats`: Tests log statistics API (winlog/pktlog counts over time)

- **Rule Reload** (`reload_test.go`):
  - `TestRuleReloadMechanism`: Tests complete rule lifecycle (add → update → delete) and verifies reload signals

- **Domain Management** (`domain_test.go`): Tests AD domain configuration

- **Rule Management** (`rule_test.go`): Tests alert rule and activity rule CRUD operations

- **Other modules**: Threat detection, scanning, users, system config, sensors, reports, notifications

## Standalone Tools

See `cmd/README.md` for standalone test executables that can be run independently without the go test framework.
