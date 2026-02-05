package common

// DomainPwdKeyGCM must match the backend-side key for domain LDAP password encryption.
const DomainPwdKeyGCM = "3a43d7a31b3ca37d9f2e8b5c1a6d4e7f"

// ScannerRunPath is the default runtime directory for scanner artifacts.
const ScannerRunPath = "/var/lib/scada"

// ScannerPkgDecryptKey must match the packaging key used to encrypt sc_enc.tar.gz/venv_enc.tar.gz.
const ScannerPkgDecryptKey = "G0pRA3dhZcdQDF1S"

// ScannerConfPathEnv is the env var that overrides scanner config path.
const ScannerConfPathEnv = "SCANNER_CONF_PATH"

// ScannerDefaultConfPath is used when ScannerConfPathEnv is not set.
const ScannerDefaultConfPath = "./scanner.yaml"

// ScannerEnvRedisURI overrides Redis URI in scanner.yaml.
const ScannerEnvRedisURI = "REDIS_URI"

// ScannerEnvMongoURI overrides Mongo URI in scanner.yaml.
const ScannerEnvMongoURI = "MONGO_URI"

// ScannerEnvMongoDBURI is a fallback override for Mongo URI in scanner.yaml.
const ScannerEnvMongoDBURI = "MONGODB_URI"

// ScannerConcurrencyEnv controls scgo worker concurrency.
const ScannerConcurrencyEnv = "SCANNER_CONCURRENCY"

// ScannerRedisRandKey is used for runtime verification in Redis.
const ScannerRedisRandKey = "ada:rand_key"
