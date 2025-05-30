db = db.getSiblingDB("db_ada");

/** tb_user indexes **/
/** default user: adaegis/adaegis **/
db.createCollection("tb_user");
db.getCollection("tb_user").createIndex({ _id: NumberInt(1) });
db.getCollection("tb_user").insert([
    {
        "_id": NumberInt(1),
        "username":"adaegis",
        "password":"$2a$04$/R7xyXXygMOk4.fv9bA11uUG.KN94IjpcOzZbhYkSYEX4pf.BQe.a",
        "pass_strength":"low",
        "role":"mgr",
        "priv": NumberInt(1),
        "mobile":"12345678901",
        "email":"admin@adaegis.net",
        "remark":"adaegis default admin",
        "create_tm":new Date(),
        "secret":"",
        "mfa_status":"disable",
        "avatar":"",
        "pwd_update_tm":new Date(),
        "real_name":"Adaegis",
        "department":"Adaegis",
        "post":"Adaegis",
        "address":"Adaegis"
    }
]);

/** tb_system_info indexes **/
db.createCollection("tb_system_info");
db.getCollection("tb_system_info").createIndex({ _id: NumberInt(1) }, { name: "_id_" });
db.getCollection("tb_system_info").insert([
    {
        "_id": new ObjectId(),
        "system_ip":"ADA_SERVER_IP",
        "system_name":"Adaegis",
        "system_icon":"",
        "system_version":"ADA_SERVER_VERSION",
        "upgrade_url":"https://upgrade.adaegis.net/check",
        "create_tm":new Date(),
        "upgrade_tm":new Date(),
        "ntp_address":"ntp.adaegis.net",
        "system_language":"ZH",
        "stats_cfg":{
            "es_cpu_percent_notify":"85",
            "es_disk_percent_delete":"90",
            "es_disk_percent_notify":"85",
            "mem_percent_notify":"85",
            "cpu_percent_notify":"85",
            "disk_percent_notify":"85"
        },
    }
]);

/** tb_seq_counters indexes **/
db.createCollection("tb_seq_counters");
db.getCollection("tb_seq_counters").createIndex({ _id: NumberInt(1) }, { name: "_id_" });
db.getCollection("tb_seq_counters").insert([
    {
        "_id": "tb_user",
        "seq": NumberInt(1)
    }
]);

/** tb_sensor indexes **/
db.createCollection("tb_sensor");
db.getCollection("tb_sensor").createIndex({ _id: NumberInt(1) }, { name: "_id_" });

/** tb_domain indexes **/
db.createCollection("tb_domain");
db.getCollection("tb_domain").createIndex({ _id: NumberInt(1) }, { name: "_id_" });

/** tb_export_task indexes **/
db.createCollection("tb_export_task");
db.getCollection("tb_export_task").createIndex({ _id: NumberInt(1) }, { name: "_id_" });

/** tb_notify indexes **/
db.createCollection("tb_notify");
db.getCollection("tb_notify").createIndex({ _id: NumberInt(1) }, { name: "_id_" });

/** tb_audit_log indexes **/
db.createCollection("tb_audit_log");
db.getCollection("tb_audit_log").createIndex({ _id: NumberInt(1) }, { name: "_id_" });

/** tb_alert_block indexes **/
db.createCollection("tb_alert_block");
db.getCollection("tb_alert_block").createIndex({ _id: NumberInt(1) }, { name: "_id_" });

/** tb_alert_event indexes **/
db.createCollection("tb_alert_event");
db.getCollection("tb_alert_event").createIndex({ _id: NumberInt(1) }, { name: "_id_" });

/** tb_alert_activity indexes **/
db.createCollection("tb_alert_activity");
db.getCollection("tb_alert_activity").createIndex({ _id: NumberInt(1) }, { name: "_id_" });

/** tb_alert_whitelist indexes **/
db.createCollection("tb_alert_whitelist");
db.getCollection("tb_alert_whitelist").createIndex({ _id: NumberInt(1) }, { name: "_id_" });

/** tb_alert_desc indexes **/
db.createCollection("tb_alert_desc");
db.getCollection("tb_alert_desc").createIndex({ _id: NumberInt(1) }, { name: "_id_" });

/** tb_asset_user indexes **/
db.createCollection("tb_asset_user");
db.getCollection("tb_asset_user").createIndex({ _id: NumberInt(1) }, { name: "_id_" });

/** tb_scan_conf indexes **/
db.createCollection("tb_scan_conf");
db.getCollection("tb_scan_conf").createIndex({ _id: NumberInt(1) }, { name: "_id_" });
db.getCollection("tb_scan_conf").insert([
    {
        "_id": new ObjectId(),
        "name": "基线定时检测配置",
        "type": "baseline",
        "rate": NumberInt(50),
        "cycle_type": NumberInt(2),
        "is_enable": true,
        "plans": {},
        "desc": "按照设置的时间周期对基线事件进行周期性检测",
        "run_time": "02:10",
        "task_fun": "ScannerBaselineTask",
        "create_tm": new Date(),
        "update_tm": new Date()
    },
    {
        "_id": new ObjectId(),
        "name": "漏洞定时检测配置",
        "type": "leak",
        "rate": NumberInt(50),
        "cycle_type": NumberInt(2),
        "is_enable": true,
        "plans": {},
        "desc": "按照设置的时间周期对漏洞事件进行周期性检测",
        "run_time": "02:20",
        "task_fun": "ScannerLeakTask",
        "create_tm": new Date(),
        "update_tm": new Date()
    },
    {
        "_id": new ObjectId(),
        "name": "弱口令定时检测配置",
        "type": "weakpwd",
        "rate": NumberInt(35),
        "cycle_type": NumberInt(2),
        "is_enable": true,
        "plans": {},
        "desc": "按照设置的时间周期对弱口令事件进行周期性检测",
        "run_time": "02:30",
        "task_fun": "ScannerWeakPwdTask",
        "create_tm": new Date(),
        "update_tm": new Date()
    }
]);

/** tb_scan_template indexes **/
db.createCollection("tb_scan_template");
db.getCollection("tb_scan_template").createIndex({ _id: NumberInt(1) }, { name: "_id_" });
db.getCollection("tb_scan_template").insert([
    {
        "_id": new ObjectId(),
        "name":"默认基线检测模板",
        "type":"baseline",
        "plugins":[],
        "create_tm": new Date(),
        "update_tm": new Date()
    },
    {
        "_id": new ObjectId(),
        "name":"默认漏洞检测模板",
        "type":"leak",
        "plugins":[],
        "create_tm": new Date(),
        "update_tm": new Date()
    },
    {
        "_id": new ObjectId(),
        "name":"默认弱口令检测模板",
        "type":"weakpwd",
        "plugins":[],
        "create_tm": new Date(),
        "update_tm": new Date()
    }
]);


/** tb_scan_plugin indexes **/
db.createCollection("tb_scan_plugin");
db.getCollection("tb_scan_plugin").createIndex({ _id: NumberInt(1) }, { name: "_id_" });

/** tb_scan_subtasks indexes **/
db.createCollection("tb_scan_subtasks");
db.getCollection("tb_scan_subtasks").createIndex({ _id: NumberInt(1) }, { name: "_id_" });

/** tb_scan_tasks indexes **/
db.createCollection("tb_scan_tasks");
db.getCollection("tb_scan_tasks").createIndex({ _id: NumberInt(1) }, { name: "_id_" });

/** tb_sensitive_entry indexes **/
db.createCollection("tb_sensitive_entry");
db.getCollection("tb_sensitive_entry").createIndex({ _id: NumberInt(1) }, { name: "_id_" });

/** tb_notify_conf indexes **/
db.createCollection("tb_notify_conf");
db.getCollection("tb_notify_conf").createIndex({ _id: NumberInt(1) });
db.getCollection("tb_notify_conf").insert([
    {
        "_id" : new ObjectId(),
        "module_name" : "alert",
        "notify_type" : "email",
        "endpoint" : "",
        "metadata" : {},
        "remark" : "该功能需要配置通知目标的邮箱地址。",
        "enable" : "disable",
        "update_tm" : new Date(),
        "last_time" : NumberInt(1),
        "notify_level" : [
            NumberInt(2),
            NumberInt(3),
            NumberInt(4),
            NumberInt(5)
        ],
        "rule_list" : []
    },
    {
        "_id" : new ObjectId(),
        "module_name" : "alert",
        "notify_type" : "syslog",
        "endpoint" : "",
        "metadata" : {},
        "remark" : "该功能需要配置syslog服务器地址，该系统会实时将每个事件内容通过json字符串的格式发送到syslog服务器；默认为UDP514端口，也可通过“IP:端口”指定其他端口。",
        "enable" : "disable",
        "update_tm" : new Date(),
        "last_time" : NumberInt(1),
        "notify_level" : [
            NumberInt(2),
            NumberInt(3),
            NumberInt(4),
            NumberInt(5)
        ],
        "rule_list" : []
    },
    {
        "_id" : new ObjectId(),
        "module_name" : "alert",
        "notify_type" : "webhook",
        "endpoint" : "",
        "metadata" : {},
        "remark" : "该功能需要配置联动的URL，该系统通过HTTP协议将攻击行为元数据通过POST形式上传到接收端进行统一分析管理，具体字段参考相关用户手册。",
        "enable" : "disable",
        "update_tm" : new Date(),
        "last_time" : NumberInt(1),
        "notify_level" : [
            NumberInt(2),
            NumberInt(3),
            NumberInt(4),
            NumberInt(5)
        ],
        "rule_list" : []
    },
    {
        "_id" : new ObjectId(),
        "module_name" : "baseline",
        "notify_type" : "email",
        "endpoint" : "",
        "metadata" : {},
        "remark" : "该功能需要配置通知目标的邮箱地址。",
        "enable" : "disable",
        "update_tm" : new Date(),
        "last_time" : NumberInt(1),
        "notify_level" : [
            NumberInt(2),
            NumberInt(3),
            NumberInt(4)
        ],
        "rule_list" : []
    },
    {
        "_id" : new ObjectId(),
        "module_name" : "baseline",
        "notify_type" : "syslog",
        "endpoint" : "",
        "metadata" : {},
        "remark" : "该功能需要配置syslog服务器地址，该系统会实时将每个事件内容通过json字符串的格式发送到syslog服务器；默认为UDP514端口，也可通过“IP:端口”指定其他端口。",
        "enable" : "disable",
        "update_tm" : new Date(),
        "last_time" : NumberInt(1),
        "notify_level" : [
            NumberInt(2),
            NumberInt(3),
            NumberInt(4)
        ],
        "rule_list" : []
    },
    {
        "_id" : new ObjectId(),
        "module_name" : "baseline",
        "notify_type" : "webhook",
        "endpoint" : "",
        "metadata" : {},
        "remark" : "该功能需要配置联动的URL，该系统通过HTTP协议将攻击行为元数据通过POST形式上传到接收端进行统一分析管理，具体字段参考相关用户手册。",
        "enable" : "disable",
        "update_tm" : new Date(),
        "last_time" : NumberInt(1),
        "notify_level" : [
            NumberInt(2),
            NumberInt(3),
            NumberInt(4)
        ],
        "rule_list" : []
    },
    {
        "_id" : new ObjectId(),
        "module_name" : "leak",
        "notify_type" : "email",
        "endpoint" : "",
        "metadata" : {},
        "remark" : "该功能需要配置通知目标的邮箱地址。",
        "enable" : "disable",
        "update_tm" : new Date(),
        "last_time" : NumberInt(1),
        "notify_level" : [
            NumberInt(2),
            NumberInt(3),
            NumberInt(4)
        ],
        "rule_list" : []
    },
    {
        "_id" : new ObjectId(),
        "module_name" : "leak",
        "notify_type" : "syslog",
        "endpoint" : "",
        "metadata" : {},
        "remark" : "该功能需要配置syslog服务器地址，该系统会实时将每个事件内容通过json字符串的格式发送到syslog服务器；默认为UDP514端口，也可通过“IP:端口”指定其他端口。",
        "enable" : "disable",
        "update_tm" : new Date(),
        "last_time" : NumberInt(1),
        "notify_level" : [
            NumberInt(2),
            NumberInt(3),
            NumberInt(4)
        ],
        "rule_list" : []
    },
    {
        "_id" : new ObjectId(),
        "module_name" : "leak",
        "notify_type" : "webhook",
        "endpoint" : "",
        "metadata" : {},
        "remark" : "该功能需要配置联动的URL，该系统通过HTTP协议将攻击行为元数据通过POST形式上传到接收端进行统一分析管理，具体字段参考相关用户手册。",
        "enable" : "disable",
        "update_tm" : new Date(),
        "last_time" : NumberInt(1),
        "notify_level" : [
            NumberInt(2),
            NumberInt(3),
            NumberInt(4)
        ],
        "rule_list" : []
    },
    {
        "_id" : new ObjectId(),
        "module_name" : "system",
        "notify_type" : "email",
        "endpoint" : "",
        "metadata" : {},
        "remark" : "该功能需要配置通知目标的邮箱地址。",
        "enable" : "disable",
        "update_tm" : new Date(),
        "last_time" : NumberInt(1),
    },
    {
        "_id" : new ObjectId(),
        "module_name" : "system",
        "notify_type" : "syslog",
        "endpoint" : "",
        "metadata" : {},
        "remark" : "该功能需要配置syslog服务器地址，该系统会实时将每个事件内容通过json字符串的格式发送到syslog服务器；默认为UDP514端口，也可通过“IP:端口”指定其他端口。",
        "enable" : "disable",
        "update_tm" : new Date(),
        "last_time" : NumberInt(1),
    },
    {
        "_id" : new ObjectId(),
        "module_name" : "system",
        "notify_type" : "webhook",
        "endpoint" : "",
        "metadata" : {},
        "remark" : "该功能需要配置联动的URL，该系统通过HTTP协议将攻击行为元数据通过POST形式上传到接收端进行统一分析管理，具体字段参考相关用户手册。",
        "enable" : "disable",
        "update_tm" : new Date(),
        "last_time" : NumberInt(1),
    },
]);
