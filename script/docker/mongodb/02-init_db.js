db = db.getSiblingDB("db_ada");

/** tb_user indexes **/
/** default user: adaegis/adaegis123 **/
db.createCollection("tb_user");
db.getCollection("tb_user").createIndex({ _id: NumberInt(1) });
db.getCollection("tb_user").insert([
    {
        _id: NumberInt(1),
        username: "adaegis",
        password:
            "$2a$10$zc.jpq8VpnhZuH1zXsN.su/vzfPaUtJlVM1jCiVvqi0ISCa3kuIqC",
        pass_strength: "low",
        role: "mgr",
        priv: NumberInt(1),
        mobile: "12345678901",
        email: "admin@adaegis.net",
        remark: "adaegis default admin",
        create_tm: new Date(),
        secret: "",
        mfa_status: "disable",
        avatar: "",
        pwd_update_tm: new Date(),
        department: "Adaegis",
        update_tm: new Date(),
    },
]);

/** tb_system_info indexes **/
db.createCollection("tb_system_info");
db.getCollection("tb_system_info").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);
db.getCollection("tb_system_info").insert([
    {
        _id: new ObjectId(),
        system_ip: "ADA_SERVER_IP",
        system_name: "Adaegis",
        system_icon: "/logo.svg",
        system_version: "ADA_SERVER_VERSION",
        upgrade_srv: "https://upgrade.adaegis.net",
        upgrade_rule: true,
        create_tm: new Date(),
        upgrade_tm: new Date(),
        ntp_address: "ntp.adaegis.net",
        system_language: "EN",
        stats_cfg: {
            es_cpu_percent_notify: "85",
            es_disk_percent_delete: "90",
            es_disk_percent_notify: "85",
            mem_percent_notify: "85",
            cpu_percent_notify: "85",
            disk_percent_notify: "85",
        },
        system_proxy: {
            http_proxy: "",
            https_proxy: "",
            upgrade_proxy: "false",
            notify_proxy: "false",
        },
    },
]);

/** tb_seq_counters indexes **/
db.createCollection("tb_seq_counters");
db.getCollection("tb_seq_counters").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);
db.getCollection("tb_seq_counters").insert([
    {
        _id: "tb_user",
        seq: NumberInt(1),
    },
]);

/** tb_sensor indexes **/
db.createCollection("tb_sensor");
db.getCollection("tb_sensor").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_domain indexes **/
db.createCollection("tb_domain");
db.getCollection("tb_domain").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_export_task indexes **/
db.createCollection("tb_export_task");
db.getCollection("tb_export_task").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_notify indexes **/
db.createCollection("tb_notify");
db.getCollection("tb_notify").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_audit_log indexes **/
db.createCollection("tb_audit_log");
db.getCollection("tb_audit_log").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_alert_block indexes **/
db.createCollection("tb_alert_block");
db.getCollection("tb_alert_block").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_alert_event indexes **/
db.createCollection("tb_alert_event");
db.getCollection("tb_alert_event").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_alert_activity indexes **/
db.createCollection("tb_alert_activity");
db.getCollection("tb_alert_activity").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_alert_whitelist indexes **/
db.createCollection("tb_alert_whitelist");
db.getCollection("tb_alert_whitelist").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_alert_rule indexes **/
db.createCollection("tb_alert_rule");
db.getCollection("tb_alert_rule").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_activity_rule indexes **/
db.createCollection("tb_activity_rule");
db.getCollection("tb_activity_rule").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_asset_user indexes **/
db.createCollection("tb_asset_user");
db.getCollection("tb_asset_user").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_scan_conf indexes **/
db.createCollection("tb_scan_conf");
db.getCollection("tb_scan_conf").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);
db.getCollection("tb_scan_conf").insert([
    {
        _id: new ObjectId(),
        name: "基线定时检测配置",
        type: "baseline",
        cycle_type: NumberInt(2),
        is_enable: true,
        plans: {},
        run_time: "02:10",
        task_fun: "ScannerBaselineTask",
        create_tm: new Date(),
        update_tm: new Date(),
    },
    {
        _id: new ObjectId(),
        name: "漏洞定时检测配置",
        type: "leak",
        cycle_type: NumberInt(2),
        is_enable: true,
        plans: {},
        run_time: "02:20",
        task_fun: "ScannerLeakTask",
        create_tm: new Date(),
        update_tm: new Date(),
    },
    {
        _id: new ObjectId(),
        name: "弱口令定时检测配置",
        type: "weakpwd",
        cycle_type: NumberInt(2),
        is_enable: true,
        plans: {},
        run_time: "02:30",
        task_fun: "ScannerWeakPwdTask",
        create_tm: new Date(),
        update_tm: new Date(),
    },
]);

/** tb_scan_template indexes **/
db.createCollection("tb_scan_template");
db.getCollection("tb_scan_template").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);
db.getCollection("tb_scan_template").insert([
    {
        _id: new ObjectId(),
        name: "Default Baseline Template",
        type: "baseline",
        plugins: [],
        create_tm: new Date(),
        update_tm: new Date(),
    },
    {
        _id: new ObjectId(),
        name: "Default Leak Template",
        type: "leak",
        plugins: [],
        create_tm: new Date(),
        update_tm: new Date(),
    },
    {
        _id: new ObjectId(),
        name: "Default WeakPwd Template",
        type: "weakpwd",
        plugins: [],
        create_tm: new Date(),
        update_tm: new Date(),
    },
]);

/** tb_scan_plugin indexes **/
db.createCollection("tb_scan_plugin");
db.getCollection("tb_scan_plugin").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_scan_subtasks indexes **/
db.createCollection("tb_scan_subtasks");
db.getCollection("tb_scan_subtasks").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_scan_tasks indexes **/
db.createCollection("tb_scan_tasks");
db.getCollection("tb_scan_tasks").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_sensitive_entry indexes **/
db.createCollection("tb_sensitive_entry");
db.getCollection("tb_sensitive_entry").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_notify_conf indexes **/
db.createCollection("tb_notify_conf");
db.getCollection("tb_notify_conf").createIndex({ _id: NumberInt(1) });

/** tb_asset_group indexes **/
db.createCollection("tb_asset_group");
db.getCollection("tb_asset_group").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_asset_computer indexes **/
db.createCollection("tb_asset_computer");
db.getCollection("tb_asset_computer").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_system_logs indexes **/
db.createCollection("tb_system_logs");
db.getCollection("tb_system_logs").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);

/** tb_access_key indexes **/
db.createCollection("tb_access_key");
db.getCollection("tb_access_key").createIndex(
    { _id: NumberInt(1) },
    { name: "_id_" },
);
