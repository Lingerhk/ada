// See the file "COPYING" in the main distribution directory for copyright.

#ifndef IOSOURCE_PKTSRC_TRAFFIC_OVER_UDP_SOURCE_H
#define IOSOURCE_PKTSRC_TRAFFIC_OVER_UDP_SOURCE_H

#define LINKTYPE_ETHERNET 1 // this is the linktype for Ethernet

extern "C" {
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <errno.h>          // errorno
#include <unistd.h>         // close()

#include <net/ethernet.h>      // ETH_P_ALL
}

#include "zeek/iosource/PktSrc.h"

namespace zeek::iosource::pktsrc {

class TrafficReceiverSource : public zeek::iosource::PktSrc {
public:
	/**
	 * Constructor.
	 *
	 * path: Name of the interface to open (the TrafficReceiver source doesn't
	 * support reading from files).
	 *
	 * is_live: Must be true (the AF_Packet source doesn't support offline
	 * operation).
	 */
	TrafficReceiverSource(const std::string& path, bool is_live);

	/**
	 * Destructor.
	 */
	virtual ~TrafficReceiverSource();

	static PktSrc* InstantiateTrafficReceiver(const std::string& path, bool is_live);

protected:
	// PktSrc interface.
	virtual void Open();
	virtual void Close();
	virtual bool ExtractNextPacket(zeek::Packet* pkt);
	virtual void DoneWithPacket();
	virtual bool PrecompileFilter(int index, const std::string& filter);
	virtual bool SetFilter(int index);
	virtual void Statistics(Stats* stats);

private:
	Properties props;
	Stats stats;

	int current_filter;

	unsigned int num_discarded;

	int socket_fd;
	struct pcap_pkthdr current_hdr;
	bool swapped;

};

}

#endif
