#include "RedisWriter.h"
#include "zeek/threading/SerialTypes.h"
#include "zeek/zeek-config.h"
#include <cstring>
#include <errno.h>
#include <map>
#include <regex>
#include <string>
#include <vector>
#include <time.h>

using namespace logging;
using namespace writer;
using zeek::threading::Field;
using zeek::threading::Value;

// The Constructor is called once for each log filter that uses this log writer.
RedisWriter::RedisWriter(zeek::logging::WriterFrontend *frontend) : zeek::logging::WriterBackend(frontend) {
  io = std::shared_ptr<zeek::threading::formatter::Ascii>(
      new zeek::threading::formatter::Ascii(
          this, zeek::threading::formatter::Ascii::SeparatorInfo()));
  /**
   * We need thread-local copies of all user-defined settings coming from zeek
   * scripting land.  accessing these is not thread-safe and 'DoInit' is
   * potentially accessed from multiple threads.
   */

  redis_host.assign((const char *)zeek::BifConst::Redis::redis_host->Bytes(),
                    zeek::BifConst::Redis::redis_host->Len());
  redis_port = zeek::BifConst::Redis::redis_port;
  redis_db = zeek::BifConst::Redis::redis_db;
  redis_password.assign((const char *)zeek::BifConst::Redis::redis_password->Bytes(),
                    zeek::BifConst::Redis::redis_password->Len());
  pool_size = zeek::BifConst::Redis::pool_size;
  pool_connection_lifetime = zeek::BifConst::Redis::pool_connection_lifetime;

  redis_key_prefix.assign((const char *)zeek::BifConst::Redis::redis_key_prefix->Bytes(),
                    zeek::BifConst::Redis::redis_key_prefix->Len());
  redis_push_type.assign((const char *)zeek::BifConst::Redis::redis_push_type->Bytes(),
                    zeek::BifConst::Redis::redis_push_type->Len());

  // json_timestamps
  zeek::ODesc tsfmt;
  zeek::BifConst::Redis::json_timestamps->Describe(&tsfmt);
  json_timestamps.assign((const char *)tsfmt.Bytes(), tsfmt.Size());

  // Initialize queue size
  const int MAX_QUEUE_SIZE = 1024 * 64; // 64KB
}

RedisWriter::~RedisWriter() {
  // Cleanup must happen in DoFinish, not in the destructor
}

std::string RedisWriter::LookupParam(const WriterInfo& info, const std::string name) const
{
	std::map<const char*, const char*>::const_iterator it = info.config.find(name.c_str());
	if ( it == info.config.end() )
		return std::string();
	else
		return it->second;
	}

/**
 * DoInit is called once for each call to the constructor, but in a separate
 * thread
 */
bool RedisWriter::DoInit(const WriterInfo &info, int num_fields,
                         const zeek::threading::Field *const *fields) {

  // TimeFormat object, format to TS_MILLIS(for elasticsearch)
  zeek::threading::formatter::JSON::TimeFormat tf =
      zeek::threading::formatter::JSON::TS_MILLIS;

  formatter = new zeek::threading::formatter::JSON(this, tf);

  // redis global configuration
  sw::redis::ConnectionOptions connection_options;

  connection_options.host = redis_host;
  connection_options.port = redis_port;
  connection_options.password = redis_password;
  connection_options.db = redis_db;
  connection_options.keep_alive = true;
  sw::redis::ConnectionPoolOptions pool_options;

  pool_options.size = pool_size;
  pool_options.wait_timeout = std::chrono::milliseconds(1000);

  if (redis_push_type != "RPUSH" && redis_push_type != "LPUSH") {
      Error(Fmt("RedisWriter::DoInit: Invalid Redis push_type %s", redis_push_type.c_str()));
      return false;
  }

  redis_client = std::make_shared<sw::redis::Redis>(connection_options);
  MsgThread::Info(Fmt("Successfully connected to Redis instance, %s to %s", redis_push_type.c_str(), redis_key_prefix.c_str()));

  return true;
}

/**
 * Writer-specific method called just before the threading system is
 * going to shutdown. It is assumed that once this messages returns,
 * the thread can be safely terminated. As such, all resources created must be
 * removed here.
 */
bool RedisWriter::DoFinish(double network_time) {
  return true;
}

std::tuple<bool, std::string, int> RedisWriter::CreateParams(const Value* val)
	{
	static std::regex curly_re("\\\\|\"");

	if ( ! val->present )
		return std::make_tuple(false, std::string(), 0);

	std::string retval;
	int retlength = 0;

	switch ( val->type ) {

	case zeek::TYPE_BOOL:
		retval = val->val.int_val ? "T" : "F";
		break;

	case zeek::TYPE_INT:
		retval = std::to_string(val->val.int_val);
		break;

	case zeek::TYPE_COUNT:
		retval = std::to_string(val->val.uint_val);
		break;

	case zeek::TYPE_PORT:
		retval = std::to_string(val->val.port_val.port);
		break;

	case zeek::TYPE_SUBNET:
		retval = io->Render(val->val.subnet_val);
		break;

	case zeek::TYPE_ADDR:
		retval = io->Render(val->val.addr_val);
		break;

	case zeek::TYPE_TIME:
	case zeek::TYPE_INTERVAL:
	case zeek::TYPE_DOUBLE:
		retval = std::to_string(val->val.double_val);
		break;

	case zeek::TYPE_ENUM:
	case zeek::TYPE_STRING:
	case zeek::TYPE_FILE:
	case zeek::TYPE_FUNC:
		retval = std::string(val->val.string_val.data, val->val.string_val.length);
		break;

	case zeek::TYPE_TABLE:
	case zeek::TYPE_VECTOR:
		{
		zeek_int_t size;
		Value** vals;

		std::string out("{");
		retlength = 1;

		if ( val->type == zeek::TYPE_TABLE )
			{
			size = val->val.set_val.size;
			vals = val->val.set_val.vals;
			}
		else
			{
			size = val->val.vector_val.size;
			vals = val->val.vector_val.vals;
			}

		if ( ! size )
			return std::make_tuple(false, std::string(), 0);

		for ( int i = 0; i < size; ++i )
			{
			if ( i != 0 )
				out += ", ";

			auto res = CreateParams(vals[i]);
			if ( std::get<0>(res) == false )
				{
				out += "NULL";
				continue;
				}

			std::string resstr = std::get<1>(res);
			zeek::TypeTag type = vals[i]->type;
			// for all numeric types, we do not need escaping
			if ( type == zeek::TYPE_BOOL || type == zeek::TYPE_INT || type == zeek::TYPE_COUNT ||
					type == zeek::TYPE_PORT || type == zeek::TYPE_TIME ||
					type == zeek::TYPE_INTERVAL || type == zeek::TYPE_DOUBLE )
				out += resstr;
			else
				{
				std::string escaped = std::regex_replace(resstr, curly_re, "\\$&");
				out += "\"" + escaped + "\"";
				retlength += 2+escaped.length();
				}
			}

		out += "}";
		retlength += 1;
		retval = out;
		break;
		}

	default:
		Error(Fmt("unsupported field format %d", val->type ));
		return std::make_tuple(false, std::string(), 0);
	}

	if ( retlength == 0 )
		retlength = retval.length();

	return std::make_tuple(true, retval, retlength);
	}

// try to get hostname by ip from local cache.
std::string RedisWriter::GetHostnameFromCache(const std::string& ip) {
  // Check if the key is in the local cache
  auto it = localCache.find(ip);
  if (it != localCache.end()) {
    return it->second;
  }

  // If not found in the local cache, try to get from Redis
  auto resp_h = redis_client->get(Fmt("%s:engine:dc_ip:%s", redis_key_prefix.c_str(), ip.c_str()));
  if (resp_h) {
    // Update the local cache
    localCache[ip] = *resp_h;
    return *resp_h;
  }

  // If still not found, return an empty string
  return "";
}

/**
 * Writer-specific output method implementing recording of one log
 * entry.
 */
bool RedisWriter::DoWrite(int num_fields, const zeek::threading::Field *const *fields,
                          zeek::threading::Value **vals) {
  std::vector<std::tuple<bool, std::string, int>>
      params; // vector in which we compile the string representation of
              // characters

  zeek::ODesc buff;
  int queue_length = 0;
  int queue_fulled = 0;
  buff.Clear();

  for (int i = 0; i < num_fields; ++i)
    params.push_back(CreateParams(vals[i]));

  // Get hostname from the local cache or Redis
  std::string hostname = GetHostnameFromCache(std::get<1>(params[4]));
  if (hostname.empty()) {
    hostname = GetHostnameFromCache(std::get<1>(params[2]));
  }

  // format the log entry
  //formatter->DescribeV2(&buff, num_fields, fields, vals, hostname);
  formatter->Describe(&buff, num_fields, fields, vals);
  const char *raw = (const char *)buff.Bytes();
  // send the formatted log entry to redis
  std::string entry = raw;
  
  // Insert hostname at the beginning of the JSON object
  // Make sure the string is a JSON object that starts with "{"
  if (!entry.empty() && entry[0] == '{') {
    // Insert after the opening brace
    entry.insert(1, "\"Hostname\":\"" + hostname + "\",");
  }

  // check if the queue is full every 10 seconds
  time_t current_time = time(nullptr);
  if (current_time % 10 == 0) {
    queue_length = redis_client->llen(Fmt("%s:pktlog_queue", redis_key_prefix.c_str()));
    if (queue_length > MAX_QUEUE_SIZE) {
      queue_fulled = 1;
    }
  }

  // RPUSH
  if (strcmp(redis_push_type.c_str(), "RPUSH") == 0) {
    if (queue_fulled) {
      redis_client->ltrim(Fmt("%s:pktlog_queue", redis_key_prefix.c_str()), 1024*10, -1); //  remove the first 1024*10 entries
    }
    redis_client->rpush(Fmt("%s:pktlog_queue", redis_key_prefix.c_str()), entry);
  } else {
    // LPUSH
    if (queue_fulled) {
      redis_client->ltrim(Fmt("%s:pktlog_queue", redis_key_prefix.c_str()), 0, -1024*10); //  remove the last 1024*10 entries
    }
    redis_client->lpush(Fmt("%s:pktlog_queue", redis_key_prefix.c_str()), entry);
  }

  // publish the log entry to redis
  redis_client->publish(Fmt("%s:pktlog_channel", redis_key_prefix.c_str()), hostname+"::"+entry);

  return true;
}

/**
 * Writer-specific method implementing a change of the buffering
 * state.	If buffering is disabled, the writer should attempt to
 * write out information as quickly as possible even if doing so may
 * have a performance impact. If enabled (which is the default), it
 * may buffer data as helpful and write it out later in a way
 * optimized for performance. The current buffering state can be
 * queried via IsBuf().
 */
bool RedisWriter::DoSetBuf(bool enabled) {
  // no change in behavior
  return true;
}

/**
 * Writer-specific method implementing flushing of its output.	A writer
 * implementation must override this method but it can just
 * ignore calls if flushing doesn't align with its semantics.
 */
bool RedisWriter::DoFlush(double network_time) {
  // no change in behavior
  return true;
}

/**
 * Writer-specific method implementing log rotation.	Most directly
 * this only applies to writers writing into files, which should then
 * close the current file and open a new one.	However, a writer may
 * also trigger other apppropiate actions if semantics are similar.
 * Once rotation has finished, the implementation *must* call
 * FinishedRotation() to signal the log manager that potential
 * postprocessors can now run.
 */
bool RedisWriter::DoRotate(const char *rotated_path, double open, double close,
                           bool terminating) {
  // no need to perform log rotation
  FinishedRotation();
  return true;
}

/**
 * Triggered by regular heartbeat messages from the main thread.
 */
bool RedisWriter::DoHeartbeat(double network_time, double current_time) {
  // no change in behavior
  return true;
}
