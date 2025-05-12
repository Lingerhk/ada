#doc-common-start
module Redis;

export {
# doc-options-start
    const json_timestamps: JSON::TimestampFormat = JSON::TS_MILLIS &redef;

    const redis_host: string = "192.168.6.139" &redef;
    const redis_port: count = 6379 &redef;
    const redis_db: count = 0 &redef;
    const redis_password: string = "1pa2YgE3jfTbVVpn06CN" &redef;

    const redis_key_prefix: string = "ada" &redef;
    const redis_push_type: string = "LPUSH" &redef;

    const pool_size: count = 3 &redef;
    const pool_connection_lifetime: count = 10 &redef;
# doc-options-end
}
