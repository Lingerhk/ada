# @TEST-EXEC: zeek -NN Zeek::TrafficReceiver |sed -e 's/version.*)/version)/g' > output
# @TEST-EXEC: btest-diff output
