#! /bin/bash


zeek_version="7.1.0"
current_dir=$(pwd)
zeek_dir="${current_dir}/zeek-${zeek_version}"

# update the local zeek source code

function download_zeek() {
    if [ ! -d "${zeek_dir}" ]; then
        echo "Downloading Zeek ${zeek_version}..."
        wget https://github.com/zeek/zeek/releases/download/v${zeek_version}/zeek-${zeek_version}.tar.gz
        tar -xzf zeek-${zeek_version}.tar.gz
        mv zeek-${zeek_version} ${zeek_dir}
    fi
}


function modify_cfg_zeekctl() {
    # modify: auxil/zeekctl/etc/zeekctl.cfg.in
    target_file="${zeek_dir}/auxil/zeekctl/etc/zeekctl.cfg.in"
    sed -i 's/FileExtractDir = .*/FileExtractDir =/' ${target_file}
}

function modify_cfg_local_zeek() {
    # modify: scripts/site/local.zeek
    target_file="${zeek_dir}/scripts/site/local.zeek"
    
    sed -i 's/^@load/#@load/g' ${target_file}

    echo "# Enable JSON logs(by adaegis)" >> ${target_file}
    echo "@load tuning/json-logs" >> ${target_file}

    # Add code to disable analyzers
    cat << EOF >> ${target_file}

# Disable analyzers(by adaegis)
redef Analyzer::disabled_analyzers += {
    Analyzer::ANALYZER_SYSLOG,
    Analyzer::ANALYZER_HTTP,
    Analyzer::ANALYZER_DHCP,
    Analyzer::ANALYZER_DNS,
    Analyzer::ANALYZER_FTP,
    Analyzer::ANALYZER_MQTT,
    Analyzer::ANALYZER_IRC,
    Analyzer::ANALYZER_MYSQL,
    Analyzer::ANALYZER_QUIC,
    Analyzer::ANALYZER_SIP,
    Analyzer::ANALYZER_SNMP,
    Analyzer::ANALYZER_SSH,
    Analyzer::ANALYZER_DNP3_TCP,
    Analyzer::ANALYZER_FINGER,
    Analyzer::ANALYZER_IMAP,
    Analyzer::ANALYZER_MODBUS,
    Analyzer::ANALYZER_MQTT,
    Analyzer::ANALYZER_NTP,
    Analyzer::ANALYZER_POP3,
    Analyzer::ANALYZER_RADIUS,
    Analyzer::ANALYZER_RFB,
    Analyzer::ANALYZER_SMTP,
    Analyzer::ANALYZER_SOCKS,
    Analyzer::ANALYZER_SSL,
    Analyzer::ANALYZER_DTLS,
    Analyzer::ANALYZER_XMPP
};

redef Analyzer::disabled_analyzers += {
    Files::ANALYZER_DATA_EVENT,
    Files::ANALYZER_ENTROPY,
    Files::ANALYZER_EXTRACT,
    Files::ANALYZER_MD5,
    Files::ANALYZER_SHA1,
    Files::ANALYZER_SHA256,
    Files::ANALYZER_PE,
    Files::ANALYZER_OCSP_REPLY,
    Files::ANALYZER_OCSP_REQUEST,
    Files::ANALYZER_X509
};
EOF
}

function modify_cfg_init_default() {
    # modify: scripts/base/init-default.zeek
    target_file="${zeek_dir}/scripts/base/init-default.zeek"

    sed -i 's/^@load base\/protocols\/dhcp/#@load base\/protocols\/dhcp/g' ${target_file}

    sed -i 's/^@load base\/protocols\/dnp3/#@load base\/protocols\/dnp3/g' ${target_file}
    sed -i 's/^@load base\/protocols\/dns/#@load base\/protocols\/dns/g' ${target_file}
    sed -i 's/^@load base\/protocols\/finger/#@load base\/protocols\/finger/g' ${target_file}
    sed -i 's/^@load base\/protocols\/ftp/#@load base\/protocols\/ftp/g' ${target_file}
    sed -i 's/^@load base\/protocols\/http/#@load base\/protocols\/http/g' ${target_file}
    sed -i 's/^@load base\/protocols\/imap/#@load base\/protocols\/imap/g' ${target_file}
    sed -i 's/^@load base\/protocols\/irc/#@load base\/protocols\/irc/g' ${target_file}

    sed -i 's/^@load base\/protocols\/modbus/#@load base\/protocols\/modbus/g' ${target_file}
    sed -i 's/^@load base\/protocols\/mqtt/#@load base\/protocols\/mqtt/g' ${target_file}
    sed -i 's/^@load base\/protocols\/mysql/#@load base\/protocols\/mysql/g' ${target_file}

    sed -i 's/^@load base\/protocols\/ntp/#@load base\/protocols\/ntp/g' ${target_file}
    sed -i 's/^@load base\/protocols\/pop3/#@load base\/protocols\/pop3/g' ${target_file}
    sed -i 's/^@load base\/protocols\/quic/#@load base\/protocols\/quic/g' ${target_file}
    sed -i 's/^@load base\/protocols\/radius/#@load base\/protocols\/radius/g' ${target_file}

    sed -i 's/^@load base\/protocols\/rfb/#@load base\/protocols\/rfb/g' ${target_file}
    sed -i 's/^@load base\/protocols\/sip/#@load base\/protocols\/sip/g' ${target_file}
    sed -i 's/^@load base\/protocols\/snmp/#@load base\/protocols\/snmp/g' ${target_file}

    sed -i 's/^@load base\/protocols\/smtp/#@load base\/protocols\/smtp/g' ${target_file}
    sed -i 's/^@load base\/protocols\/socks/#@load base\/protocols\/socks/g' ${target_file}
    sed -i 's/^@load base\/protocols\/ssh/#@load base\/protocols\/ssh/g' ${target_file}
    sed -i 's/^@load base\/protocols\/ssl/#@load base\/protocols\/ssl/g' ${target_file}
    sed -i 's/^@load base\/protocols\/syslog/#@load base\/protocols\/syslog/g' ${target_file}
    sed -i 's/^@load base\/protocols\/tunnels/#@load base\/protocols\/tunnels/g' ${target_file}
    sed -i 's/^@load base\/protocols\/xmpp/#@load base\/protocols\/xmpp/g' ${target_file}
    
    sed -i 's/^@load base\/files\/pe/#@load base\/files\/pe/g' ${target_file}
    sed -i 's/^@load base\/files\/hash/#@load base\/files\/hash/g' ${target_file}
    sed -i 's/^@load base\/files\/extract/#@load base\/files\/extract/g' ${target_file}
    sed -i 's/^@load base\/files\/x509/#@load base\/files\/x509/g' ${target_file}

    sed -i 's/^@load base\/misc\/find-checksum-offloading/#@load base\/misc\/find-checksum-offloading/g' ${target_file}
    sed -i 's/^@load base\/misc\/find-filtered-trace/#@load base\/misc\/find-filtered-trace/g' ${target_file}
    sed -i 's/^@load base\/misc\/installation/#@load base\/misc\/installation/g' ${target_file}
    sed -i 's/^@load base\/misc\/version/#@load base\/misc\/version/g' ${target_file}
}


function modify_cfg_ldap_main() {
    # modify: scripts/base/protocols/ldap/main.zeek
    target_file="${zeek_dir}/scripts/base/protocols/ldap/main.zeek"

    sed -i "s/option default_capture_password = F;/option default_capture_password = T;/g" ${target_file}
    sed -i "s/option default_log_search_attributes = F;/option default_log_search_attributes = T;/g" ${target_file}
}

function modify_cfg_logger_ascii() {
    # modify: scripts/base/frameworks/logging/writers/ascii.zeek
    target_file="${zeek_dir}/scripts/base/frameworks/logging/writers/ascii.zeek"

    sed -i 's/const json_timestamps: JSON::TimestampFormat = JSON::TS_EPOCH &redef;/const json_timestamps: JSON::TimestampFormat = JSON::TS_MILLIS &redef;/g' ${target_file}
}

function modify_zeek() {
    cd ${zeek_dir}
    modify_cfg_zeekctl;
}

function build_zeek() {
    cd ${zeek_dir}
    ./configure
    make -j 8
    make install
}


function main() {
    download_zeek;
    build_zeek;



}


main $@