##! Packet source using Traffic over UDP.
##!
##! Note: This module is in testing and is not yet considered stable!

module TrafficReceiver;

export {
	## Size of the socket-buffer.
	const buffer_size = 32 * 1024 &redef;
}
