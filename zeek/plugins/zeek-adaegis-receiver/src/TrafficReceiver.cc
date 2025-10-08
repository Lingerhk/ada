#include "zeek/zeek-config.h"
#include "zeek/DebugLogger.h"
#include "Plugin.h"
#include "zeek/util.h"

// For HTTP request
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// Starting with Zeek 6.0, zeek-config.h does not provide the
// ZEEK_VERSION_NUMBER macro anymore when compiling a included
// plugin. Use the new zeek/zeek-version.h header if it exists.
#if __has_include("zeek/zeek-version.h")
#include "zeek/zeek-version.h"
#endif

#include "TrafficReceiver.h"

#include "trafficreceiver.bif.h"

static int zpot_set_socket_buffer_size(int socket_fd);
static int zpot_get_bind_ip_and_port(const std::string & path, std::string &bind_ip, int * port);
static int zpot_bind_local_udp_socket(int socket_fd, std::string local_ip, int port_number); // add by s0nnet.
static int zpot_get_packet_body(int socket_fd, char * buffer, int bufsize);
static int zpot_http_request(const std::string& url, std::string& response);

using namespace zeek::iosource::pktsrc;

plugin::Zeek_TrafficReceiver::Plugin TrafficReceiverFoo;

TrafficReceiverSource::~TrafficReceiverSource()
{
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "Destructor: Entry");
	Close();
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "Destructor: Exit");
}

//
//	Constructor -- just sets up and instantiates the object.
//
//	We don't actually open the socket until Open() is called.
//
TrafficReceiverSource::TrafficReceiverSource(const std::string& path, bool is_live)
{
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "Constructor: Entry");
	// does Traffic over UDP support live or non-live traffic?
	if ( ! is_live )
		Error("TrafficReceiver source does not support offline input");

	current_filter = -1;
	props.path = path;
	props.is_live = is_live;

	PLUGIN_DBG_LOG(TrafficReceiverFoo, "Constructor: Exit");
}

// 	open the socket as a packet source
void TrafficReceiverSource::Open()
{
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "Open: Entry");

	// try connecy to  `http://localhost:8801/lic/trait`, if status code is not 200, then return.
	//std::string url = "http://ada_backend:8801/lic/trait";
	//std::string response;
	
	//PLUGIN_DBG_LOG(TrafficReceiverFoo, "Open: Checking license at %s", url.c_str());
	//int status_code = zpot_http_request(url, response);
	
	//if (status_code != 200)
	//{
	//	PLUGIN_DBG_LOG(TrafficReceiverFoo, "Open: License check failed with status code %d", status_code);
	//	Error(errno ? strerror(errno) : "License validation failed");
	//	return;
	//}
	
	//PLUGIN_DBG_LOG(TrafficReceiverFoo, "Open: License check successful");

	// create socket
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "Open: creating socket");
	socket_fd = socket(AF_INET, SOCK_DGRAM, 0); // for udp

	if ( socket_fd < 0 )
	{
		Error(errno ? strerror(errno) : "unable to create socket");
		return;
	}


	// set the socket params
	int rv = zpot_set_socket_buffer_size(socket_fd);
	if (rv < 0)
	{
		Error(errno ? strerror(errno) : "warning: unable to set socket opts");
	}

	// bind to local ip as a server
	std::string bind_ip;
	int port;

	// get IP address and port to connect to
	if (zpot_get_bind_ip_and_port(props.path, bind_ip, &port) < 0)
	{
		Error(errno ? strerror(errno) : "Invalid DNSNAME:PORT address format");
		return;
	}

	// bind local udp socket
	if (zpot_bind_local_udp_socket(socket_fd, bind_ip, port) < 0)
	{
		Error(errno ? strerror(errno) : "unable to bind local udp socket");
		close(socket_fd);
		return;
	}

	// fill in props
	props.netmask = NETMASK_UNKNOWN;
	props.selectable_fd = socket_fd;
	props.is_live = true;
	props.link_type = LINKTYPE_ETHERNET;

	stats.received = stats.dropped = stats.link = stats.bytes_received = 0;
	num_discarded = 0;

	Opened(props);
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "Open: Exit");
}

void TrafficReceiverSource::Close()
{
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "Close: Entry");
	if ( ! socket_fd )
		return;

	close(socket_fd);
	socket_fd = 0;

	Closed();
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "Close: Exit");
}

// refer to zeek-af_packet-plugin/src/AF_Packet.cc
bool TrafficReceiverSource::ExtractNextPacket(zeek::Packet* pkt)
{
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "ExtractNext: Entry");
	if ( ! socket_fd ) 
	{
		PLUGIN_DBG_LOG(TrafficReceiverFoo, "ExtractNext: socket is closed");
		return false;
	}

	char buffer[16*1024];

	while ( true )
	{
		// read the next packet off the socket
		memset(&buffer, 0, sizeof(buffer));
		const u_char *data = (u_char *) buffer;
		int bytes_received;

		// now read the full packet
		bytes_received = zpot_get_packet_body(socket_fd, buffer, sizeof(buffer));
		if (bytes_received < 0) 
		{
			Error(errno ? strerror(errno) : "error reading socket3");
			return false;
		}
	
		// EOF is presumably caught above, so by definition don't need this,
		// but this hack seems to work.  Here, bytes = 0 does NOT equal EOF, just try again.
		if (bytes_received == 0) 
		{
			// socket has no bytes on the packet read.  Give up and loop again.
			PLUGIN_DBG_LOG(TrafficReceiverFoo, "ExtractNext: OOD2");
			return false;
		}

		// apply the BFF Filter
		// if ( !ApplyBPFFilter(current_filter, &current_hdr, data) )
		// {
		// 	++num_discarded;
		// 	DoneWithPacket();
		// 	continue;
		// }

		double now = zeek::util::current_time(true);
		struct timeval current_ts;
        current_ts.tv_sec = static_cast<time_t>(now);
        current_ts.tv_usec = static_cast<suseconds_t>((now - current_ts.tv_sec) * 1e6);

		// call pkt-Init()
		pkt->Init(props.link_type, &current_ts, bytes_received, bytes_received, data);

		// update stats
		stats.received++;
		stats.bytes_received += bytes_received;

		PLUGIN_DBG_LOG(TrafficReceiverFoo, "ExtractNext: Exit");
		return true;
	}

	// NOTREACHED
	return false;
}

void TrafficReceiverSource::DoneWithPacket()
{
	// Nothing to do.
}

bool TrafficReceiverSource::SetFilter(int index)
{
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "SetFilter: Open");
	current_filter = index;
	return true;
}

bool TrafficReceiverSource::PrecompileFilter(int index, const std::string& filter)
{
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "Precompile: Open");
	return PktSrc::PrecompileBPFFilter(index, filter);
}

// get the statistics for the packet source
void TrafficReceiverSource::Statistics(Stats* s)
{
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "Stats: Open");
	if ( ! socket_fd )
	{
		s->received = s->bytes_received = s->link = s->dropped = 0;
		return;
	}

	memcpy(s, &stats, sizeof(Stats));
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "Stats: Exit");
}

zeek::iosource::PktSrc* TrafficReceiverSource::InstantiateTrafficReceiver(const std::string& path, bool is_live)
{
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "Instantiate: Entry");
	return new TrafficReceiverSource(path, is_live);
}

// set the socket buffer size
static int zpot_set_socket_buffer_size(int socket_fd)
{
    // get options
    int request_buffer_size = zeek::BifConst::TrafficReceiver::buffer_size;
    int current_buffer_size;
	unsigned int option_len = sizeof(current_buffer_size);
    int rv;

	PLUGIN_DBG_LOG(TrafficReceiverFoo, "zpot_set_socket_buffer_size: entry");
    // get the current socket params
    rv = getsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &current_buffer_size, &option_len);
    //static_cast<socklen_t>(sizeof(current_buffer_size)));
    if (rv < 0)
    {
        PLUGIN_DBG_LOG(TrafficReceiverFoo,"zpot_set_socket_buffer_size: error retrieving buffer");
        return -1;
    }

    // is request more than current?
    if (request_buffer_size < current_buffer_size)
    {
        PLUGIN_DBG_LOG(TrafficReceiverFoo, "zpot_set_socket_buffer_size: request %d is smaller than current %d", request_buffer_size, current_buffer_size);
        return -1;
    }

    // set the current socket params
    rv = setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &request_buffer_size, sizeof(request_buffer_size));
    if (rv < 0)
	{
		PLUGIN_DBG_LOG(TrafficReceiverFoo, "zpot_set_socket_buffer_size: error setting buffer size");
		return -1;
	}
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "zpot_set_socket_buffer_size: set to %d", request_buffer_size);
	return 0;
}

//	get the server DNS name and port number.  -1 means error, 0 OK
static int zpot_get_bind_ip_and_port(const std::string& path, std::string &bind_ip, int * port)
{
	// find the DNS name and port of server
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "zpot_get_bind_ip_and_port: path is %s", path.c_str());
	size_t colon_pos = path.find(':');
	if (colon_pos == std::string::npos) 
	{
		return -1;
	}

	// Extract the DNS name and port number as separate strings
	bind_ip = path.substr(0, colon_pos);
	std::string port_str = path.substr(colon_pos + 1);
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "zpot_get_bind_ip_and_port: bind_ip %s, port %s", bind_ip.c_str(), port_str.c_str());

	// Convert the port number string to an integer
	int port_number = std::stoi(port_str);
	PLUGIN_DBG_LOG(TrafficReceiverFoo, "zpot_get_bind_ip_and_port: port_number is %d", port_number );
	*port = port_number;
	return 0;
}

// bind local udp socket
static int zpot_bind_local_udp_socket(int socket_fd, std::string bind_ip, int port_number)
{
    PLUGIN_DBG_LOG(TrafficReceiverFoo, "zpot_bind_local_udp_socket: Binding... ");
    
    // Setup server_addr for UDP
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET; // Set to AF_INET for UDP
    server_addr.sin_addr.s_addr = inet_addr(bind_ip.c_str());
    server_addr.sin_port = htons(port_number);

    int rv = bind(socket_fd, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr));
    if (rv < 0)
    {
        PLUGIN_DBG_LOG(TrafficReceiverFoo, "zpot_bind_local_udp_socket: bind failed");
        return -1;
    }
    PLUGIN_DBG_LOG(TrafficReceiverFoo, "zpot_bind_local_udp_socket: bind success");
    return 0;
}

// 	get the full packet from the socket. Return bytes_received:
// 	< 0 : error
// 	  0 : socket is closed, EOF
static int zpot_get_packet_body(int socket_fd, char * buffer, int bufsize)
{
	int bytes_received;

	do {
		bytes_received = recv(socket_fd, buffer, bufsize, 0);
	} while ((bytes_received == -1) && (errno == EINTR));

	PLUGIN_DBG_LOG(TrafficReceiverFoo, "zpot_get_packet_body: bytes_received is %d", bytes_received);
	if (bytes_received < 0)
	{
		PLUGIN_DBG_LOG(TrafficReceiverFoo, "zpot_get_packet_body: errno is %d (%s)", errno, strerror(errno));
		return -1;
	}

	// EOF will probably be caught above, so probably don't need this,
	// but just in case...
	if (bytes_received == 0)
	{
		// socket has no data, which shouldn't happen?
		return 0;
	}

	return bytes_received; // return the full size of the packet
}

// Simple HTTP GET request function
static int zpot_http_request(const std::string& url, std::string& response)
{
    // Parse URL: "http://localhost:8801/lic/trait"
    std::string host;
    std::string path;
    int port = 8801;
    
    // Find host
    size_t host_start = url.find("://");
    if (host_start != std::string::npos)
    {
        host_start += 3; // move past "://"
    }
    else
    {
        host_start = 0;
    }
    
    // Find port and path
    size_t port_start = url.find(":", host_start);
    size_t path_start = url.find("/", host_start);
    
    if (port_start != std::string::npos && port_start < path_start) 
    {
        host = url.substr(host_start, port_start - host_start);
        port = std::stoi(url.substr(port_start + 1, path_start - port_start - 1));
    }
    else 
    {
        host = url.substr(host_start, path_start - host_start);
    }
    
    path = url.substr(path_start);
    
    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) 
    {
        PLUGIN_DBG_LOG(TrafficReceiverFoo, "HTTP request: Socket creation failed");
        return -1;
    }
    
    // Set timeout
    struct timeval tv;
    tv.tv_sec = 2;  // 2 seconds timeout
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);
    
    // Get host address
    struct hostent *server = gethostbyname(host.c_str());
    if (server == NULL) 
    {
        PLUGIN_DBG_LOG(TrafficReceiverFoo, "HTTP request: Cannot resolve host %s", host.c_str());
        close(sock);
        return -1;
    }
    
    // Set up server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(port);
    
    // Connect to server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) 
    {
        PLUGIN_DBG_LOG(TrafficReceiverFoo, "HTTP request: Connection failed to %s:%d", host.c_str(), port);
        close(sock);
        return -1;
    }
    
    // Create HTTP request
    std::string request = "GET " + path + " HTTP/1.1\r\n";
    request += "Host: " + host + "\r\n";
    request += "Connection: close\r\n\r\n";
    
    // Send request
    if (send(sock, request.c_str(), request.length(), 0) != (ssize_t)request.length()) 
    {
        PLUGIN_DBG_LOG(TrafficReceiverFoo, "HTTP request: Failed to send request");
        close(sock);
        return -1;
    }
    
    // Receive response
    char buffer[4096];
    std::string http_response;
    ssize_t bytes_received;
    
    while ((bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) 
    {
        buffer[bytes_received] = '\0';
        http_response += buffer;
    }
    
    close(sock);
    
    // Parse response status code
    int status_code = -1;
    if (!http_response.empty()) 
    {
        // HTTP/1.1 200 OK
        size_t pos = http_response.find(" ");
        if (pos != std::string::npos && pos + 1 < http_response.length()) 
        {
            std::string status_str = http_response.substr(pos + 1, 3);
            try 
            {
                status_code = std::stoi(status_str);
                response = http_response;
            } 
            catch (...) 
            {
                PLUGIN_DBG_LOG(TrafficReceiverFoo, "HTTP request: Failed to parse status code");
            }
        }
    }
    
    PLUGIN_DBG_LOG(TrafficReceiverFoo, "HTTP request: Got status code %d", status_code);
    return status_code;
}


