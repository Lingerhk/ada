

# generate redis tls cert
./gen-test-certs.sh


# testing the redis tls conf:
redis-cli --tls --cert redis.crt --key redis.key --cacert ca.crt  -p 9091
