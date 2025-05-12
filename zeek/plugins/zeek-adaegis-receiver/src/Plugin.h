
#ifndef ZEEK_PLUGIN_ADAEGIS_RECEIVER
#define ZEEK_PLUGIN_ADAEGIS_RECEIVER

#include <zeek/plugin/Plugin.h>	

namespace plugin::Zeek_TrafficReceiver {

class Plugin : public zeek::plugin::Plugin
{
protected:
	// Overridden from zeek::plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}

#endif
