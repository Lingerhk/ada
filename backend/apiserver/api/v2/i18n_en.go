package v2

// I18nLangEnMap define the i18n message for english
var I18nLangEnMap = map[string]any{
	// common define
	"Success":         "Success",
	"Unknown":         "Unknown",
	"InternalError":   "Internal error",
	"QueryFailed":     "Query failed",
	"NoPermission":    "No permission",
	"ParseFailed":     "Parse failed",
	"AlreadyExists":   "Already exists",
	"NotFound":        "Resource not found",
	"DeleteFailed":    "Delete failed",
	"UpdateFailed":    "Update failed",
	"CommandFailed":   "Command failed",
	"GetFailed":       "Get failed",
	"LicenseExpired":  "License expired",
	"InvalidArgument": "Invalid argument",
	"RpcClientFailed": "RPC client failed",
	"RpcTaskFailed":   "RPC task failed",

	// Sensor module
	"Sensor": map[string]any{
		"UpdateSensor": map[string]any{
			"EmptyIface": "Empty iface",
		},
		"CmdSensor": map[string]any{
			"UninstallFailed": "Uninstall failed, please uninstall manually on AD!",
		},
		"UpdateSensorVersion": map[string]any{
			"SensorNotRunning":       "Sensor not running",
			"VersionError":           "Version error",
			"GetLatestVersionFailed": "Get latest version failed",
		},
	},
	// Domain module
	"Domain": map[string]any{
		"PasswordSaveError":    "Password save error",
		"UpdateScanConfFailed": "Update scan config failed",
		"DomainStatusError":    "Domain status error",
		"InvalidCredentials":   "Invalid username or password",
		"PasswordEncryptError": "Encryption error",
		"UpdateDomainData": map[string]any{
			"LDAPAddrError": "LDAP address error",
		},
		"TestDomain": map[string]any{
			"TestErrorInvalidCredentials": "Test Error: Invalid username or password",
			"TestErrorNetwork":            "Test Error: LDAP address error",
			"TestErrorTimeout":            "Test Error: Connection timeout, please check DNS address",
			"TestErrorUnknown":            "Test Error: Unknown error",
			"TestSuccess":                 "Test Success",
		},
		"UpdateDomain": map[string]any{
			"DeleteKeyFailed":      "Delete domain key failed",
			"LDAPParseFailed":      "Validation failed",
			"StatusSyncTaskFailed": "Domain status sync task failed",
			"LDAPSyncTaskFailed":   "Domain asset sync task failed",
		},
		"DeploySensor": map[string]any{
			"DcHostnameNotFound":       "DC hostname not found",
			"DcHostnameNotOnline":      "DC hostname is not online",
			"SensorAlreadyInstalled":   "Sensor already installed",
			"PasswordDecodeError":      "Password decode error",
			"DcHostnameNoIP":           "DC hostname has no IP addresses",
			"SensorInstallationFailed": "Sensor installation failed",
		},
	},

	// User module
	"User": map[string]any{
		"LoginErrorLocked":    "Login error locked for 5 minutes",
		"UsernameExists":      "Username already exists",
		"PasswordLengthError": "Password length does not meet the requirements, please enter a password of at least 8 characters",
		"InvalidUsername":     "Invalid username",
		"InvalidPassword":     "Invalid password",
		"InvalidMfaCode":      "Invalid mfa code",
		"Login": map[string]any{
			"InvalidCredentials":   "Invalid username or password",
			"EmptyMfaCode":         "Empty mfa code",
			"MfaCodeError":         "Invalid mfa code",
			"MfaCodeGenerateError": "MFA code generation error",
		},
		"AddUser": map[string]any{
			"UsernameAndPasswordEmpty": "Username and password cannot be empty",
			"RoleEmpty":                "Role cannot be empty",
			"AddUserFailed":            "Add user failed",
		},
		"UpdateUser": map[string]any{
			"GetUserInfoFailed": "Get user info failed",
			"UpdateUserFailed":  "Update user failed",
		},
		"UpdateUserPassword": map[string]any{
			"EncryptPasswordError": "Encrypt password error",
			"UpdatePasswordFailed": "Update password failed",
		},
		"DeleteUser": map[string]any{
			"CannotDeleteSelf": "Cannot delete self",
			"DeleteUserFailed": "Delete user failed",
		},
		"MfaCodeGenerateError": "MFA code generation error",
		"EnableMfa": map[string]any{
			"UpdateSecretFailed": "Update MFA secret failed",
		},
		"DisableMfa": map[string]any{
			"DisableFailed": "Disable MFA failed",
		},
		"UpdateAvatar": map[string]any{
			"UploadFailed":    "Upload avatar failed",
			"FileTooLarge":    "Avatar file too large, please upload an image smaller than 512KB",
			"InvalidFileType": "Only JPG, JPEG, PNG image files can be uploaded",
		},
		"GetPwdUpdateTm": map[string]any{
			"UserNotFound": "User information not found",
		},
	},

	// Notify module
	"Notify": map[string]any{
		"TestNotifyConf": map[string]any{
			"EmailDailyLimit":          "(%s email) Daily email limit reached",
			"WebhookResponseCodeError": "Request sent, but response code was abnormal: %d",
		},
	},

	// Report module
	"Report": map[string]any{
		"AddExportTask": map[string]any{
			"AddFailed": "Add export task failed",
		},
		"DeleteExportTask": map[string]any{
			"DeleteFailed": "Delete export task failed",
		},
	},

	// ScanRisk module
	"ScanRisk": map[string]any{
		"DataParseError":        "Data parse error",
		"GetScanTaskListFailed": "Get scan task list failed",
		"GetScanTaskFailed":     "Get scan task failed",
		"ListBaseline": map[string]any{
			"GetBaselineFailed":     "Get baseline failed",
			"GetBaselineListFailed": "Get baseline list failed",
		},
		"GetBaseline": map[string]any{
			"GetBaselineFailed": "Get baseline failed",
		},
		"ListLeak": map[string]any{
			"GetLeakFailed":     "Get leak failed",
			"GetLeakListFailed": "Get leak list failed",
		},
		"ListWeakPwd": map[string]any{
			"GetWeakPwdFailed":     "Get weakpwd failed",
			"GetWeakPwdListFailed": "Get weakpwd list failed",
		},
		"ScanConf": map[string]any{
			"GetScanConfFailed": "Get scan conf failed",
			"UpdateFailed":      "Update scan conf failed",
		},
		"ScanTmpl": map[string]any{
			"GetScanTmplNamesFailed": "Get scan tmpl names failed",
			"GetScanTmplFailed":      "Get scan tmpl failed",
			"UpdateFailed":           "Update scan tmpl failed",
			"DefaultTmplNotDelete":   "Default scan tmpl cannot be deleted",
			"DeleteFailed":           "Delete scan tmpl failed",
			"NameExists":             "Scan tmpl name already exists",
			"AddFailed":              "Add scan tmpl failed",
		},
		"ScanPlugin": map[string]any{
			"GetScanPluginFailed": "Get scan plugin failed",
		},
		"AddScanTask": map[string]any{
			"NameNotFound":    "name not found",
			"InvalidCronConf": "Invalid cron config",
			"EmptyDomainList": "Domain list cannot be empty",
		},
		"RecheckScanTask": map[string]any{
			"GetLatestTaskFailed": "Get latest task failed: %v",
			"GetSubTaskFailed":    "Get sub-tasks failed",
		},
		"DeleteScanTask": map[string]any{
			"DeleteFailed": "Delete failed: %v",
		},
	},

	// System module
	"System": map[string]any{
		"GetSystemInfoFailed":        "Get system info failed",
		"GetSystemIconFailed":        "Get system icon failed",
		"UpdateSystemIconFailed":     "Update system icon failed",
		"UpdateIconTooLarge":         "Upload icon file too large, please upload an image smaller than 512KB",
		"UpdateIconInvalidType":      "Upload icon file type not supported (only jpg/jpeg/png format)",
		"UpdateNtpAddressFailed":     "Update ntp address failed",
		"UpdateSystemLanguageFailed": "Update system language failed",
		"UpdateSystemIPFailed":       "Update system ip failed",
		"NetworkDebug": map[string]any{
			"InvalidTarget": "Invalid target",
			"TargetTooLong": "Target too long (more than 25 characters)",
			"NcSyntax":      "NC command syntax is IP:Port",
			"Timeout":       "Request command timeout (limit 60 seconds)",
		},
		"InvalidStatsItem":     "Invalid stats item(%s)",
		"UpdateStatsCfgFailed": "Update stats cfg failed",
		"ScanPlugin": map[string]any{
			"GetScanPluginFailed": "Get scan plugin failed",
		},
		"ScanTask": map[string]any{
			"NameNotFound":        "Name cannot be empty",
			"InvalidCronConf":     "Invalid cron config",
			"EmptyDomainList":     "Domain name cannot be empty",
			"DeleteFailed":        "Delete failed: %v",
			"GetLatestTaskFailed": "Get latest task failed: %v",
			"GetSubTaskFailed":    "Get sub-tasks failed",
		},
		"License": map[string]any{
			"GetLicenseFailed":    "Get license failed",
			"InvalidLicenseKey":   "Invalid license key",
			"UpdateLicenseFailed": "Update license failed",
		},
	},

	// Threat module
	"Threat": map[string]any{
		"ParseFilterFailed": "Parse filter failed",
		"QueryFailed":       "Query failed",
		"UpdateFailed":      "Update failed",
		"InvalidID":         "Invalid ID",
		"EventProcessed":    "Event processed",
		"Activity": map[string]any{
			"QueryFailed":            "Query failed",
			"ParseFilterFailed":      "Parse filter failed",
			"GetActivityNamesFailed": "Get activity names failed",
		},
		"ThreatRule": map[string]any{
			"GetThreatRuleNamesFailed": "Get threat rule names failed",
		},
		"AlertRule": map[string]any{
			"QueryFailed":            "Query alert rules failed",
			"InvalidDetectionFormat": "Invalid detection YAML format",
			"AddFailed":              "Add alert rule failed",
			"UpdateFailed":           "Update alert rule failed",
			"DeleteFailed":           "Delete alert rule failed",
		},
		"ActivityRule": map[string]any{
			"QueryFailed":            "Query activity rules failed",
			"NotFound":               "Activity rule not found",
			"GetDetailFailed":        "Get rule detail failed",
			"InvalidDetectionFormat": "Invalid detection YAML format",
			"AddFailed":              "Add activity rule failed",
			"UpdateFailed":           "Update activity rule failed",
			"DeleteFailed":           "Delete activity rule failed",
		},
		"SensitiveEntry": map[string]any{
			"GetSensitiveEntryListFailed": "Get sensitive entry list failed",
			"DomainNameEmpty":             "Domain and name cannot be empty",
			"AlreadyExists":               "Domain list already exists",
			"AddSensitiveEntryFailed":     "Add sensitive entry failed",
			"TypeInvalid":                 "Type error, currently only supports user",
			"GetDomainEntryFailed":        "Get domain entry failed",
			"GetSensitiveEntryFailed":     "Get sensitive entry failed",
			"DeleteSensitiveEntryFailed":  "Delete sensitive entry failed",
		},
		"Whitelist": map[string]any{
			"RuleExists": "Rule already exists",
		},
		"ThreatBlock": map[string]any{
			"SensorOffline":  "All sensors under the domain are offline",
			"DeleteFailed":   "Delete blocking policy failed",
			"NoChange":       "No change",
			"UpdateFailed":   "Update blocking policy failed",
			"AddFailed":      "Add blocking policy failed",
			"DomainNotExist": "Domain not found",
			"UserListEmpty":  "User block list cannot be empty",
			"IpListEmpty":    "IP block list cannot be empty",
		},
	},
}
