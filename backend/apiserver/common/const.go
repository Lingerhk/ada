package common

// 常量定义
const (
	JWT_SECRET = "EDAcBXKdKn2fcqWH"
)

// login config
const (
	LoginErrorCount = 4       //登录错误次数限制
	LoginExpired    = 60 * 12 // jwt token expire time in minutes
)

// return status
const (
	RESP_SUCCESS = "success"
	RESP_FAILED  = "failed"
)

// 用户角色定义
const (
	RoleOps = "ops"
	RoleSec = "sec"
	RoleMgr = "mgr"
)

// 用户权限等级定义
const (
	PrivSuper = 1
	PrivUser  = 2
)

// 威胁事件状态
const (
	RiskStatusPending   = 0 // 待处理
	RiskStatusFinished  = 1 // 已处理
	RiskStatusWhitelist = 2 // 已加白
	RiskStatusBlocked   = 3 // 已阻断
)
