

# 打包zeek docker images

### dev 6.4
docker build -t ada_zeek:dev6.4 .
docker save 8863688254fc > ada_zeek_dev.tar

# docker load < ada_zeek_dev.tar


# run 
docker run -d --restart=always -p 9093:9093/udp --name ada_zeek ada_zeek:dev6.4
