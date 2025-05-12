#! /bin/bash

# Make sure the hiredis and redis-plus-plus is installed in /usr/local
# Install hiredis
#```shell`
# apt install -y libhiredis-dev
# wget https://github.com/sewenew/redis-plus-plus/archive/refs/tags/1.3.12.tar.gz  -O /tmp/redis-plus-plus-1.3.12.tar.gz
# cd /tmp && tar -xzf redis-plus-plus-1.3.12.tar.gz 
# cd redis-plus-plus-1.3.12
# mkdir -p build
# cd build
# cmake ..
# make
# sudo make install
#```

# build according to zeek source code dependency:
./configure --enable-debug --zeek-dist=/home/adadmin/zeek/zeek-7.1.0

### Build
export PATH=/usr/local/zeek/bin:$PATH
./configure --enable-debug --with-redisplusplus=/usr/local
make
sudo make install
