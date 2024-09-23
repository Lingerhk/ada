
## middle service
systemctl status redis-server
systemctl status mongod
systemctl status elasticsearch
systemctl status kibana
systemctl status nginx

## ada service
/usr/local/zeek/bin/zeekctl status

supervisorctl status receiver
supervisorctl status apiserver
supervisorctl status task_server
supervisorctl status task_worker
supervisorctl status engine
supervisorctl status scanner
