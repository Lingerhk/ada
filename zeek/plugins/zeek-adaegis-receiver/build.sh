#! /bin/bash


# build according to zeek source code dependency:
./configure --enable-debug --zeek-dist=/home/adadmin/zeek/zeek-7.1.0


export PATH=/usr/local/zeek/bin:$PATH
./configure --enable-debug
make
sudo make install