/** tb_notify_conf indexes **/
db.getCollection("tb_notify_conf").ensureIndex({
    "_id": NumberInt(1)
}, []);



/** tb_notify_conf records **/
db.getCollection("tb_notify_conf").insert([
    {
        "_id" : ObjectId("6108ae441f3b207330922620"),
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
        "_id" : ObjectId("6108ae441f3b207330922621"),
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
        "_id" : ObjectId("6108ae441f3b207330922622"),
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
        "_id" : ObjectId("6108ae441f3b207330922624"),
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
        "_id" : ObjectId("6108ae441f3b207330922625"),
        "module_type" : "baseline",
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
        "_id" : ObjectId("6108ae441f3b207330922626"),
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
        "_id" : ObjectId("6108ae441f3b207330922628"),
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
        "_id" : ObjectId("6108ae441f3b207330922629"),
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
        "_id" : ObjectId("6108ae441f3b207330922630"),
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
        "_id" : ObjectId("6108ae441f3b207330922632"),
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
        "_id" : ObjectId("6108ae441f3b207330922633"),
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
        "_id" : ObjectId("6108ae441f3b207330922634"),
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