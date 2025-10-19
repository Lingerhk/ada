// Build User:  lingerhk
// Build Time:  2024-03-04 17:42:31

db.tb_alert_desc.remove({});

db.tb_alert_desc.insertMany(
    [{
        "_id": "flow-0001",
        "title": "RDP Login Brute Force",
        "enable": true,
        "level": NumberInt(4),
        "auto_block": false,
        "attack_flow" : {
            "fields" : [ {
                "obj" : "user",
                "keys" : "TargetUserName"
            }, {
                "obj" : "computer",
                "keys" : "source_hostname,source_ip"
            }, {
                "obj" : "dc",
                "keys" : "Hostname"
            } ],
            "relates" : [ "来自于", "通过（DCOMEXEC）远程登录" ]
        },
        "name_en": "RDP Login Brute Force",
        "name_zh": "远程桌面（RDP）登录暴力破解",
        "event_desc_en": "在攻击过程中，攻击者会利用微软自带的 PSEXEC 远程管理工具来对域控制器进行远程命令执行并继续横向移动。",
        "event_desc_zh": "在攻击过程中，攻击者会利用微软自带的 PSEXEC 远程管理工具来对域控制器进行远程命令执行并继续横向移动。",
        "event_tmpl_en": "监测到来自于 [source_hostname,source_ip] 使用身份 [source_username,source_machine_username] 正在使用 [PSEXEC] 尝试对域控 [dc_hostname] 远程命令执行。",
        "event_tmpl_zh": "监测到来自于 [source_hostname,source_ip] 使用身份 [source_username,source_machine_username] 正在使用 [PSEXEC] 尝试对域控 [dc_hostname] 远程命令执行。",
        "type_en": "Abnormal Behavior",
        "type_zh": "异常行为",
        "suggestion_en": "1.确认RDP",
        "suggestion_zh": "1.",
        "verify_desc_en": "",
        "verify_desc_zh": ""
    },{
        "_id": "flow-0002",
        "title": "SAMR Sensitive Information Discovery",
        "enable": true,
        "level": NumberInt(4),
        "auto_block": false,
        "attack_flow" : {
            "fields" : [ {
                "obj" : "user",
                "keys" : "TargetUserName"
            }, {
                "obj" : "computer",
                "keys" : "source_hostname,source_ip"
            }, {
                "obj" : "dc",
                "keys" : "Hostname"
            } ],
            "relates" : [ "来自于", "通过（DCOMEXEC）远程登录" ]
        },
        "name_en": "SAMR Sensitive Information Discovery",
        "name_zh": "ZH--SAMR Sensitive Information Discovery",
        "event_desc_en": "在攻击过程中，攻击者会利用微软自带的 PSEXEC 远程管理工具来对域控制器进行远程命令执行并继续横向移动。",
        "event_desc_zh": "在攻击过程中，攻击者会利用微软自带的 PSEXEC 远程管理工具来对域控制器进行远程命令执行并继续横向移动。",
        "event_tmpl_en": "监测到来自于 [source_hostname,source_ip] 使用身份 [source_username,source_machine_username] 正在使用 [PSEXEC] 尝试对域控 [dc_hostname] 远程命令执行。",
        "event_tmpl_zh": "监测到来自于 [source_hostname,source_ip] 使用身份 [source_username,source_machine_username] 正在使用 [PSEXEC] 尝试对域控 [dc_hostname] 远程命令执行。",
        "type_en": "Abnormal Behavior",
        "type_zh": "异常行为",
        "suggestion_en": "1.确认RDP",
        "suggestion_zh": "1.",
        "verify_desc_en": "",
        "verify_desc_zh": ""
    },{
        "_id": "flow-0003",
        "title": "Kerberos Account Enumeration",
        "enable": true,
        "level": NumberInt(4),
        "auto_block": false,
        "attack_flow" : {
            "fields" : [ {
                "obj" : "user",
                "keys" : "source_username,source_machine_username"
            }, {
                "obj" : "computer",
                "keys" : "source_hostname,source_ip"
            }, {
                "obj" : "dc",
                "keys" : "Hostname"
            } ],
            "relates" : [ "来自于", "通过（DCOMEXEC）远程登录" ]
        },
        "name_en": "SAMR Sensitive Information Discovery",
        "name_zh": "ZH--SAMR Sensitive Information Discovery",
        "event_desc_en": "在攻击过程中，攻击者会利用微软自带的 PSEXEC 远程管理工具来对域控制器进行远程命令执行并继续横向移动。",
        "event_desc_zh": "在攻击过程中，攻击者会利用微软自带的 PSEXEC 远程管理工具来对域控制器进行远程命令执行并继续横向移动。",
        "event_tmpl_en": "监测到来自于 [source_hostname,source_ip] 使用身份 [source_username,source_machine_username] 正在使用 [PSEXEC] 尝试对域控 [dc_hostname] 远程命令执行。",
        "event_tmpl_zh": "监测到来自于 [source_hostname,source_ip] 使用身份 [source_username,source_machine_username] 正在使用 [PSEXEC] 尝试对域控 [dc_hostname] 远程命令执行。",
        "type_en": "Abnormal Behavior",
        "type_zh": "异常行为",
        "suggestion_en": "1.确认RDP",
        "suggestion_zh": "1.",
        "verify_desc_en": "",
        "verify_desc_zh": ""
    },{
        "_id": "flow-0004",
        "title": "Kerberos Password Spray",
        "enable": true,
        "level": NumberInt(4),
        "auto_block": false,
        "attack_flow" : {
            "fields" : [ {
                "obj" : "user",
                "keys" : "TargetUserName"
            }, {
                "obj" : "computer",
                "keys" : "source_hostname,source_ip"
            }, {
                "obj" : "dc",
                "keys" : "Hostname"
            } ],
            "relates" : [ "来自于", "通过（DCOMEXEC）远程登录" ]
        },
        "name_en": "SAMR Sensitive Information Discovery",
        "name_zh": "ZH--SAMR Sensitive Information Discovery",
        "event_desc_en": "在攻击过程中，攻击者会利用微软自带的 PSEXEC 远程管理工具来对域控制器进行远程命令执行并继续横向移动。",
        "event_desc_zh": "在攻击过程中，攻击者会利用微软自带的 PSEXEC 远程管理工具来对域控制器进行远程命令执行并继续横向移动。",
        "event_tmpl_en": "监测到来自于 [source_hostname,source_ip] 使用身份 [source_username,source_machine_username] 正在使用 [PSEXEC] 尝试对域控 [dc_hostname] 远程命令执行。",
        "event_tmpl_zh": "监测到来自于 [source_hostname,source_ip] 使用身份 [source_username,source_machine_username] 正在使用 [PSEXEC] 尝试对域控 [dc_hostname] 远程命令执行。",
        "type_en": "Abnormal Behavior",
        "type_zh": "异常行为",
        "suggestion_en": "1.确认RDP",
        "suggestion_zh": "1.",
        "verify_desc_en": "",
        "verify_desc_zh": ""
    },{
        "_id": "flow-0005",
        "title": "Sensitive User Login",
        "enable": true,
        "level": NumberInt(4),
        "auto_block": false,
        "attack_flow" : {
            "fields" : [ {
                "obj" : "user",
                "keys" : "TargetUserName"
            }, {
                "obj" : "ip",
                "keys" : "IpAddress"
            }, {
                "obj" : "dc",
                "keys" : "Hostname"
            } ],
            "relates" : [ "来自于", "通过（DCOMEXEC）远程登录" ]
        },
        "name_en": "Sensitive User Login",
        "name_zh": "敏感用户尝试从新位置认证",
        "event_desc_en": "在攻击过程中，攻击者会利用微软自带的 PSEXEC 远程管理工具来对域控制器进行远程命令执行并继续横向移动。",
        "event_desc_zh": "敏感用户从新的IP位置登录到DC中或发起相关认证请求，此行为若非管理员操作大概率存在安全风险，可进行排查，若为可信IP，可以进行加白处理。",
        "event_tmpl_en": "监测到来自于 [source_hostname,source_ip] 使用身份 [source_username,source_machine_username] 正在使用 [PSEXEC] 尝试对域控 [dc_hostname] 远程命令执行。",
        "event_tmpl_zh": "监测到来自于 [source_hostname,source_ip] 使用身份 [source_username,source_machine_username] 正在使用 [PSEXEC] 尝试对域控 [dc_hostname] 远程命令执行。",
        "type_en": "Abnormal Behavior",
        "type_zh": "异常行为",
        "suggestion_en": "1.确认RDP",
        "suggestion_zh": "1.",
        "verify_desc_en": "",
        "verify_desc_zh": ""
    }]
)