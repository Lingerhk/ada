package v2

// I18nLangZhMap define the i18n message for chinese
var I18nLangZhMap = map[string]any{
	// common define
	"Success":         "成功",
	"Unknown":         "未知",
	"InternalError":   "系统错误",
	"QueryFailed":     "查询失败",
	"NoPermission":    "没有权限",
	"ParseFailed":     "解析失败",
	"AlreadyExists":   "已经存在",
	"NotFound":        "资源不存在",
	"DeleteFailed":    "删除失败",
	"UpdateFailed":    "更新失败",
	"CommandFailed":   "命令执行失败",
	"GetFailed":       "获取失败",
	"LicenseExpired":  "许可证已过期",
	"InvalidArgument": "参数错误",
	"RpcClientFailed": "RPC客户端失败",
	"RpcTaskFailed":   "RPC任务失败",

	// Sensor module
	"Sensor": map[string]any{
		"UpdateSensor": map[string]any{
			"EmptyIface": "网卡不能为空",
		},
		"CmdSensor": map[string]any{
			"UninstallFailed": "卸载传感器失败，请在AD上手动卸载！",
		},
		"UpdateSensorVersion": map[string]any{
			"SensorNotRunning":       "域控传感器未处于运行中",
			"VersionError":           "版本异常",
			"GetLatestVersionFailed": "获取最新版本失败",
		},
	},
	// Domain module
	"Domain": map[string]any{
		"PasswordSaveError":    "密码存储异常",
		"UpdateScanConfFailed": "更新扫描配置失败",
		"DomainStatusError":    "域状态异常",
		"InvalidCredentials":   "用户名或密码不正确",
		"PasswordEncryptError": "加密异常",
		"UpdateDomainData": map[string]any{
			"LDAPAddrError": "ldap地址错误",
		},
		"TestDomain": map[string]any{
			"TestErrorInvalidCredentials": "测试错误: 用户名或密码不正确",
			"TestErrorNetwork":            "测试错误: ldap地址错误",
			"TestErrorTimeout":            "测试错误: 连接超时，请检查DNS地址是否正确",
			"TestErrorUnknown":            "测试错误: 未知的错误",
			"TestSuccess":                 "测试成功",
		},
		"UpdateDomain": map[string]any{
			"DeleteKeyFailed":      "删除域密钥失败",
			"LDAPParseFailed":      "验证失败",
			"StatusSyncTaskFailed": "域状态同步任务任务失败",
			"LDAPSyncTaskFailed":   "域资产同步任务任务失败",
		},
		"DeploySensor": map[string]any{
			"DcHostnameNotFound":       "域控主机名不存在",
			"DcHostnameNotOnline":      "域控主机名不在线",
			"SensorAlreadyInstalled":   "域控主机名已安装传感器",
			"PasswordDecodeError":      "域控密码解密失败",
			"DcHostnameNoIP":           "域控主机名没有IP地址",
			"SensorInstallationFailed": "执行安装传感器失败",
		},
	},

	// User module
	"User": map[string]any{
		"LoginErrorLocked":    "登录错误锁定五分钟",
		"UsernameExists":      "用户名已存在",
		"PasswordLengthError": "密码长度不符合要求，请输入8位以上密码",
		"InvalidUsername":     "用户名错误",
		"InvalidPassword":     "密码错误",
		"InvalidMfaCode":      "验证码错误",
		"Login": map[string]any{
			"InvalidCredentials":   "用户名或密码不正确",
			"EmptyMfaCode":         "未输入二次验证",
			"MfaCodeError":         "二次验证错误",
			"MfaCodeGenerateError": "验证生成异常",
		},
		"AddUser": map[string]any{
			"UsernameAndPasswordEmpty": "用户名和密码不能为空",
			"RoleEmpty":                "权限不能为空",
			"AddUserFailed":            "新增用户失败",
		},
		"UpdateUser": map[string]any{
			"GetUserInfoFailed": "获取用户信息失败",
			"UpdateUserFailed":  "更新用户失败",
		},
		"UpdateUserPassword": map[string]any{
			"EncryptPasswordError": "加密过程异常，请重试",
			"UpdatePasswordFailed": "更新密码失败",
		},
		"DeleteUser": map[string]any{
			"CannotDeleteSelf": "不能删除自己",
			"DeleteUserFailed": "删除用户失败",
		},
		"MfaCodeGenerateError": "MFA验证码生成失败",
		"EnableMfa": map[string]any{
			"UpdateSecretFailed": "更新MFA密钥失败",
		},
		"DisableMfa": map[string]any{
			"DisableFailed": "禁用失败",
		},
		"UpdateAvatar": map[string]any{
			"UploadFailed":    "上传头像失败",
			"FileTooLarge":    "上传头像文件过大，请上传小于512Kb的图片文件",
			"InvalidFileType": "仅限上传JPG，JPEG，PNG格式的图片文件",
		},
		"GetPwdUpdateTm": map[string]any{
			"UserNotFound": "未能找到用户信息",
		},
	},

	// Notify module
	"Notify": map[string]any{
		"TestNotifyConf": map[string]any{
			"EmailDailyLimit":          "（%s邮箱）每日接收邮件数量达到上限",
			"WebhookResponseCodeError": "请求已发送，但是响应Code异常：%d",
		},
	},

	// Report module
	"Report": map[string]any{
		"AddExportTask": map[string]any{
			"AddFailed": "添加导出任务失败",
		},
		"DeleteExportTask": map[string]any{
			"DeleteFailed": "删除导出任务失败",
		},
	},

	// ScanRisk module
	"ScanRisk": map[string]any{
		"DataParseError":        "数据解析出错",
		"GetScanTaskListFailed": "查询扫描任务列表失败",
		"GetScanTaskFailed":     "获取扫描任务失败",
		"ListBaseline": map[string]any{
			"GetBaselineFailed":     "获取基线失败",
			"GetBaselineListFailed": "获取基线列表失败",
		},
		"GetBaseline": map[string]any{
			"GetBaselineFailed": "获取基线失败",
		},
		"ListLeak": map[string]any{
			"GetLeakFailed":     "获取漏洞失败",
			"GetLeakListFailed": "获取漏洞列表失败",
		},
		"ListWeakPwd": map[string]any{
			"GetWeakPwdFailed":     "获取弱口令失败",
			"GetWeakPwdListFailed": "获取弱口令列表失败",
		},
		"ScanConf": map[string]any{
			"GetScanConfFailed": "获取扫描配置失败",
			"UpdateFailed":      "更新扫描配置失败",
		},
		"ScanTmpl": map[string]any{
			"GetScanTmplNamesFailed": "获取扫描模板名称失败",
			"GetScanTmplFailed":      "获取扫描模板失败",
			"UpdateFailed":           "更新扫描模板失败",
			"DefaultTmplNotDelete":   "默认模板不可删除",
			"DeleteFailed":           "删除扫描模板失败",
			"NameExists":             "条目名称已存在",
			"AddFailed":              "添加扫描模板失败",
		},
		"ScanPlugin": map[string]any{
			"GetScanPluginFailed": "获取扫描插件失败",
		},
		"AddScanTask": map[string]any{
			"NameNotFound":    "名称不能为空",
			"InvalidCronConf": "无效的定时任务配置",
			"EmptyDomainList": "域名称不能为空",
		},
		"RecheckScanTask": map[string]any{
			"GetLatestTaskFailed": "获取最新任务失败:%v",
			"GetSubTaskFailed":    "获取子任务失败",
		},
		"DeleteScanTask": map[string]any{
			"DeleteFailed": "删除失败:%v",
		},
	},

	// System module
	"System": map[string]any{
		"GetSystemInfoFailed":        "获取系统信息失败",
		"GetSystemIconFailed":        "获取系统LOGO失败",
		"UpdateSystemIconFailed":     "更新系统LOGO失败",
		"UpdateIconTooLarge":         "上传图标文件过大，请上传小于512KB的图片文件",
		"UpdateIconInvalidType":      "上传图标文件类型不支持(仅限jpg/jpeg/png格式)",
		"UpdateNtpAddressFailed":     "更新NTP地址失败",
		"UpdateSystemLanguageFailed": "更新系统语言失败",
		"UpdateSystemIPFailed":       "更新系统IP失败",
		"NetworkDebug": map[string]any{
			"InvalidTarget": "包含非法字符串",
			"TargetTooLong": "Target太长(超过25字符)",
			"NcSyntax":      "NC命令语法为IP:Port",
			"Timeout":       "请求命令超时(限制60秒)",
		},
		"InvalidStatsItem":     "无效的监控项(%s)",
		"UpdateStatsCfgFailed": "更新监控配置失败",
		"ScanPlugin": map[string]any{
			"GetScanPluginFailed": "获取扫描插件失败",
		},
		"ScanTask": map[string]any{
			"NameNotFound":        "名称不能为空",
			"InvalidCronConf":     "无效的定时任务配置",
			"EmptyDomainList":     "域名称不能为空",
			"DeleteFailed":        "删除失败:%v",
			"GetLatestTaskFailed": "获取最新任务失败:%v",
			"GetSubTaskFailed":    "获取子任务失败",
		},
		"License": map[string]any{
			"GetLicenseFailed":    "获取许可证失败",
			"InvalidLicenseKey":   "无效的许可证",
			"UpdateLicenseFailed": "更新许可证失败",
		},
	},

	// Threat module
	"Threat": map[string]any{
		"ParseFilterFailed": "解析检索条件异常",
		"QueryFailed":       "查询失败",
		"UpdateFailed":      "更新失败",
		"InvalidID":         "无效ID",
		"EventProcessed":    "事件已处理",
		"Activity": map[string]any{
			"QueryFailed":            "查询失败",
			"ParseFilterFailed":      "解析过滤条件失败",
			"GetActivityNamesFailed": "获取活动名称失败",
		},
		"ThreatRule": map[string]any{
			"GetThreatRuleNamesFailed": "获取威胁规则名称失败",
		},
		"SensitiveEntry": map[string]any{
			"GetSensitiveEntryListFailed": "获取敏感配置失败",
			"DomainNameEmpty":             "选择域和名称条目不能为空",
			"AlreadyExists":               "新增域列表已存在",
			"AddSensitiveEntryFailed":     "新增条目失败",
			"TypeInvalid":                 "类型错误,当前仅支持user",
			"GetDomainEntryFailed":        "获取域内Entry失败",
			"GetSensitiveEntryFailed":     "获取条目失败",
			"DeleteSensitiveEntryFailed":  "删除条目失败",
		},
		"Whitelist": map[string]any{
			"RuleExists": "规则已存在",
		},
		"ThreatBlock": map[string]any{
			"SensorOffline":  "域名下的传感器全部离线",
			"DeleteFailed":   "删除阻断策略失败",
			"NoChange":       "无变化",
			"UpdateFailed":   "更新阻断策略失败",
			"AddFailed":      "添加阻断策略失败",
			"DomainNotExist": "域名不存在",
			"UserListEmpty":  "用户阻断列表不能为空",
			"IpListEmpty":    "IP阻断列表不能为空",
		},
	},
}
