
#include "Plugin.h"
#include "TrafficReceiver.h"
#include "zeek/iosource/Component.h"
#include "zeek/DebugLogger.h"

plugin::Zeek_TrafficReceiver::Plugin TrafficReceiver;

namespace plugin::Zeek_TrafficReceiver { Plugin plugin; }

using namespace plugin::Zeek_TrafficReceiver;

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::zeek::iosource::PktSrcComponent("TrafficReceiverReader", "trafficreceiver", ::zeek::iosource::PktSrcComponent::LIVE, ::zeek::iosource::pktsrc::TrafficReceiverSource::InstantiateTrafficReceiver));

	zeek::plugin::Configuration config;
	config.name = "Zeek::TrafficReceiver";
	config.description = "Receives packets from adaegis";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}
