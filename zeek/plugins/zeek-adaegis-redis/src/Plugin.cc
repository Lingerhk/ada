#include "Plugin.h"
#include "RedisWriter.h"
#include "zeek/iosource/Component.h"

namespace plugin::Zeek_Redis { Plugin plugin; }

using namespace plugin::Zeek_Redis;

zeek::plugin::Configuration Plugin::Configure() {
  AddComponent(new zeek::logging::Component(
      "RedisWriter", ::logging::writer::RedisWriter::Instantiate));

  zeek::plugin::Configuration config;
  config.name = "Zeek::Redis";
  config.description = "Writes logs to redis for adaegis";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
  return config;
}
