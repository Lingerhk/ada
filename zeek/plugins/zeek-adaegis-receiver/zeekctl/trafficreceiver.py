import ZeekControl.plugin

class TrafficReceiver(ZeekControl.plugin.Plugin):
	def __init__(self):
		super(TrafficReceiver, self).__init__(apiversion=1)

	def name(self):
		return "trafficreceiver"

	def pluginVersion(self):
		return 1

	def init(self):
		# Only use the plugin if there is a worker using TrafficReceiver for load balancing.
		for nn in self.nodes():
			if nn.type == "worker" and nn.interface.startswith("trafficreceiver::") and nn.lb_procs:
				return True

		return False

	def nodeKeys(self):
		return ["fanout_id", "fanout_mode", "buffer_size"]

	def zeekctl_config(self):
		script = ""

		# Add custom configuration values per worker.
		for nn in self.nodes():
			if nn.type != "worker" or not nn.lb_procs:
				continue

			params = ""

			if nn.trafficreceiver_fanout_id:
				params += "\n  redef TrafficReceiver::fanout_id = %s;" % nn.trafficreceiver_fanout_id
			if nn.trafficreceiver_fanout_mode:
				params += "\n  redef TrafficReceiver::fanout_mode = %s;" % nn.trafficreceiver_fanout_mode
			if nn.trafficreceiver_buffer_size:
				params += "\n  redef TrafficReceiver::buffer_size = %s;" % nn.trafficreceiver_buffer_size

			if params:
				script += "\n@if( peer_description == \"%s\" ) %s\n@endif" % (nn.name, params)

		return script
