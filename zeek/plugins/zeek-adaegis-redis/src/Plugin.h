#ifndef ZEEK_PLUGIN_ADAEGIS_REDIS
#define ZEEK_PLUGIN_ADAEGIS_REDIS

#include <zeek/plugin/Plugin.h>

namespace plugin::Zeek_Redis {

    class Plugin : public zeek::plugin::Plugin
    {
    protected:
      // Overridden from plugin::Plugin.
      zeek::plugin::Configuration Configure() override;
    };

    extern Plugin plugin;
}

#endif