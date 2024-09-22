#!/bin/bash

logfile="/home/adadmin/logs/monitor.log"

# check middleware status(with systemd service)
services=("mongod.service" "redis-server.service" "elasticsearch.service" "supervisor.service" "nginx.service" "kibana.service")
for service in "${services[@]}"
do
    status=$(sudo systemctl is-active "$service")
    if [ $? -eq 0 ]; then
        echo "[$(date)] check ${service} active." >> ${logfile}
    else
        echo "[$(date)] check ${service} inactive, will try to start it." >> ${logfile}
        systemctl start ${service}
    fi
done


# check ada service status(with supervisor service)
services=("ada_receiver" "ada_engine" "ada_scanner" "ada_taskserver" "ada_taskworker" "ada_apiserver")
for service in "${services[@]}"
do
    status=$(sudo supervisorctl status "$service")
    if [ $? -eq 0 ]; then
        echo "[$(date)] check ${service} active." >> ${logfile}
    else
        echo "[$(date)] check ${service} inactive, will try to start it." >> ${logfile}
        supervisorctl start ${service}
    fi
done

echo "[$(date)] check service done, will sleep 180s..." >> ${logfile}
sleep 180s