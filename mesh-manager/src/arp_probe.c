// SPDX-License-Identifier: GPL-2.0-only
/* Observe one local IPv4 address. This deliberately does not configure it. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define LOCAL_MAC_LIMIT 256
#define RECEIVE_LIMIT 512
#define BUDGET_MS 3000
#define OBSERVE_MS 2000
#define FIRST_SEND_MS 250
#define SECOND_SEND_MS 1000
#define CHECK_MS 50
#define FRAME_LENGTH 42

struct target {
	unsigned int index;
	unsigned char mac[6];
	struct in_addr address;
	unsigned int local_count;
	unsigned char local_mac[LOCAL_MAC_LIMIT][6];
};

static const unsigned char broadcast_mac[6] = { 255, 255, 255, 255, 255, 255 };
static const unsigned char zero_mac[6];

static int unavailable(const char *reason)
{
	printf("{\"schema\":1,\"status\":\"unavailable\",\"reason\":\"%s\"}\n", reason);
	return 1;
}

static int64_t monotonic_ms(void)
{
	struct timespec time;
	if (clock_gettime(CLOCK_MONOTONIC, &time)) return -1;
	return (int64_t)time.tv_sec * 1000 + time.tv_nsec / 1000000;
}

static bool unicast_mac(const unsigned char *mac)
{
	return !(mac[0] & 1) && memcmp(mac, zero_mac, 6);
}

static bool local_mac(const struct target *target, const unsigned char *mac)
{
	for (unsigned int i = 0; i < target->local_count; i++)
		if (!memcmp(target->local_mac[i], mac, 6)) return true;
	return false;
}

static bool valid_request(int argc, char **argv, struct in_addr *address)
{
	char canonical[INET_ADDRSTRLEN];
	if (argc != 3 || !argv[1][0] || strlen(argv[1]) >= IFNAMSIZ) return false;
	for (const unsigned char *p = (const unsigned char *)argv[1]; *p; p++)
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		      (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.')) return false;
	if (inet_pton(AF_INET, argv[2], address) != 1 ||
	    !inet_ntop(AF_INET, address, canonical, sizeof(canonical)) || strcmp(canonical, argv[2])) return false;
	uint32_t host = ntohl(address->s_addr);
	return (host >> 24) != 0 && (host >> 24) != 127 && (host >> 24) < 224;
}

/* getifaddrs is local netlink only. Collect every local Ethernet MAC, including
 * inactive interfaces, so a reflected local ARP can never be a foreign claim. */
static bool snapshot(const char *interface, struct in_addr address, struct target *result)
{
	struct ifaddrs *interfaces = NULL;
	bool has_address = false, has_link = false, valid = true;
	memset(result, 0, sizeof(*result));
	result->address = address;
	result->index = if_nametoindex(interface);
	if (!result->index || getifaddrs(&interfaces)) return false;
	for (struct ifaddrs *entry = interfaces; entry; entry = entry->ifa_next) {
		if (!entry->ifa_addr) continue;
		if (entry->ifa_addr->sa_family == AF_PACKET) {
			struct sockaddr_ll *link = (struct sockaddr_ll *)entry->ifa_addr;
			if (link->sll_hatype != ARPHRD_ETHER || link->sll_halen != 6 || !unicast_mac(link->sll_addr)) continue;
			if (!local_mac(result, link->sll_addr)) {
				if (result->local_count == LOCAL_MAC_LIMIT) { valid = false; break; }
				memcpy(result->local_mac[result->local_count++], link->sll_addr, 6);
			}
			if (!strcmp(entry->ifa_name, interface) && link->sll_ifindex == (int)result->index &&
			    (entry->ifa_flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING) &&
			    !(entry->ifa_flags & IFF_LOOPBACK)) {
				memcpy(result->mac, link->sll_addr, 6);
				has_link = true;
			}
		} else if (entry->ifa_addr->sa_family == AF_INET && !strcmp(entry->ifa_name, interface)) {
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)entry->ifa_addr;
			if (ipv4->sin_addr.s_addr == address.s_addr) has_address = true;
		}
	}
	freeifaddrs(interfaces);
	/* Detect deletion/recreation while netlink's link/address dump was read. */
	return valid && has_address && has_link && if_nametoindex(interface) == result->index;
}

static bool unchanged(const char *interface, const struct target *initial)
{
	struct target current;
	if (!snapshot(interface, initial->address, &current) || current.index != initial->index ||
	    memcmp(current.mac, initial->mac, 6) || current.local_count != initial->local_count) return false;
	for (unsigned int i = 0; i < current.local_count; i++)
		if (!local_mac(initial, current.local_mac[i])) return false;
	return true;
}

static void make_probe(const struct target *target, unsigned char frame[FRAME_LENGTH])
{
	memset(frame, 0, FRAME_LENGTH);
	memcpy(frame, broadcast_mac, 6);
	memcpy(frame + 6, target->mac, 6);
	frame[12] = 0x08; frame[13] = 0x06; /* Ethernet ARP */
	frame[15] = 1; /* ARPHRD_ETHER */
	frame[16] = 0x08; /* ETH_P_IP */
	frame[18] = 6; frame[19] = 4;
	frame[21] = 1; /* ARPOP_REQUEST, with SPA/THA zero */
	memcpy(frame + 22, target->mac, 6);
	memcpy(frame + 38, &target->address.s_addr, 4);
}

/* Byte offsets avoid unaligned accesses on MIPS/ARM. Padding is permissible;
 * incomplete headers, bad address lengths and unknown opcodes are not. */
static bool claim(const unsigned char *frame, size_t length, const struct target *target,
		  const struct sockaddr_ll *sender)
{
	if (length < FRAME_LENGTH || length > 1518 || sender->sll_ifindex != (int)target->index ||
	    sender->sll_hatype != ARPHRD_ETHER || sender->sll_halen != 6 ||
	    sender->sll_pkttype == PACKET_OUTGOING || sender->sll_pkttype == PACKET_LOOPBACK ||
	    frame[12] != 0x08 || frame[13] != 0x06 || frame[14] != 0 || frame[15] != 1 ||
	    frame[16] != 0x08 || frame[17] != 0 || frame[18] != 6 || frame[19] != 4 ||
	    frame[20] != 0 || (frame[21] != 1 && frame[21] != 2) ||
	    !unicast_mac(frame + 6) || memcmp(frame + 6, frame + 22, 6) ||
	    memcmp(sender->sll_addr, frame + 6, 6) || local_mac(target, frame + 6)) return false;
	/* Only ordinary Ethernet unicast or broadcast ARP destinations are valid. */
	if (!unicast_mac(frame) && memcmp(frame, broadcast_mac, 6)) return false;
	if (!memcmp(frame + 28, &target->address.s_addr, 4)) return true;
	static const unsigned char zero_address[4];
	return frame[21] == 1 && !memcmp(frame + 28, zero_address, 4) &&
	       !memcmp(frame + 32, zero_mac, 6) && !memcmp(frame + 38, &target->address.s_addr, 4);
}

static const char *receive_packets(int socket_fd, const struct target *target, int64_t start,
				  unsigned int *received, unsigned int *claims, unsigned int limit, bool *empty)
{
	*empty = false;
	for (unsigned int batch = 0; batch < limit; batch++) {
		int64_t now = monotonic_ms();
		if (now < 0) return "receive_failed";
		if (now - start >= BUDGET_MS) return "budget_exceeded";
		unsigned char frame[2048];
		struct sockaddr_ll sender;
		socklen_t sender_length = sizeof(sender);
		memset(&sender, 0, sizeof(sender));
		ssize_t length = recvfrom(socket_fd, frame, sizeof(frame), MSG_TRUNC,
			(struct sockaddr *)&sender, &sender_length);
		if (length < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) { *empty = true; return NULL; }
			if (errno == EINTR) continue;
			return "receive_failed";
		}
		if (++*received >= RECEIVE_LIMIT) return "receive_limit";
		if (sender_length == sizeof(sender) && length <= (ssize_t)sizeof(frame) &&
		    claim(frame, (size_t)length, target, &sender)) (*claims)++;
	}
	return NULL;
}

int main(int argc, char **argv)
{
	struct in_addr address;
	struct target target;
	int64_t start = monotonic_ms(), now;
	if (start < 0) return unavailable("receive_failed");
	if (!valid_request(argc, argv, &address) || !snapshot(argv[1], address, &target))
		return unavailable("interface_unavailable");
	/* Protocol zero receives nothing until bind selects this interface's ARP;
	 * there is no temporary subscription to unrelated LAN/WAN interfaces. */
	int socket_fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (socket_fd < 0) return unavailable("socket_unavailable");
	const char *error = NULL;
	unsigned int transmitted = 0, received = 0, claims = 0;
	struct sockaddr_ll binding = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ARP),
		.sll_ifindex = (int)target.index };
	int buffer_size = 16384;
	if (bind(socket_fd, (struct sockaddr *)&binding, sizeof(binding)) ||
	    setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size))) {
		error = "socket_unavailable";
		goto done;
	}
	struct sockaddr_ll destination = binding;
	destination.sll_halen = 6;
	memcpy(destination.sll_addr, broadcast_mac, 6);
	unsigned char request[FRAME_LENGTH];
	make_probe(&target, request);
	int64_t checked = start;
	for (;;) {
		now = monotonic_ms();
		if (now < 0) { error = "receive_failed"; break; }
		if (now - start >= BUDGET_MS) { error = "budget_exceeded"; break; }
		if (now - checked >= CHECK_MS) {
			if (!unchanged(argv[1], &target)) { error = "target_changed"; break; }
			now = monotonic_ms();
			if (now < 0) { error = "receive_failed"; break; }
			if (now - start >= BUDGET_MS) { error = "budget_exceeded"; break; }
			checked = now;
		}
		/* A delayed process must not complete its transmission schedule after
		 * the observation interval has already elapsed. */
		if (now - start >= OBSERVE_MS) {
			if (transmitted != 2) { error = "budget_exceeded"; break; }
			bool empty;
			/* poll/elapsed time cannot prove the receive queue is empty. Drain
			 * already queued claims before a successful result, bounded by the
			 * same packet and monotonic budgets as the normal receive path. */
			error = receive_packets(socket_fd, &target, start, &received, &claims, RECEIVE_LIMIT, &empty);
			if (!error && !empty) error = "receive_limit";
			break;
		}
		if ((transmitted == 0 && now - start >= FIRST_SEND_MS) ||
		    (transmitted == 1 && now - start >= SECOND_SEND_MS)) {
			if (!unchanged(argv[1], &target)) { error = "target_changed"; break; }
			/* Snapshot acquisition itself can be interrupted or delayed. */
			now = monotonic_ms();
			if (now < 0) { error = "receive_failed"; break; }
			if (now - start >= OBSERVE_MS) { error = "budget_exceeded"; break; }
			ssize_t size = sendto(socket_fd, request, sizeof(request), 0,
				(struct sockaddr *)&destination, sizeof(destination));
			if (size != sizeof(request)) { error = "send_failed"; break; }
			transmitted++;
		}
		struct pollfd ready = { .fd = socket_fd, .events = POLLIN };
		int available = poll(&ready, 1, CHECK_MS);
		if (available < 0) {
			if (errno == EINTR) continue;
			error = "receive_failed"; break;
		}
		if (ready.revents & (POLLERR | POLLHUP | POLLNVAL)) { error = "receive_failed"; break; }
		if (!(ready.revents & POLLIN)) continue;
		/* One bounded batch per iteration; a flood cannot hide the deadline or
		 * interface checks. Invalid/own packets also consume the receive budget. */
		bool empty;
		error = receive_packets(socket_fd, &target, start, &received, &claims, 32, &empty);
		if (error) break;
	}
	/* Link removal/down can surface as a socket error before the next periodic
	 * check. Preserve the more useful identity-change reason in that case. */
	if (!unchanged(argv[1], &target)) error = "target_changed";
	if (!error) {
		struct tpacket_stats statistics;
		socklen_t length = sizeof(statistics);
		if (getsockopt(socket_fd, SOL_PACKET, PACKET_STATISTICS, &statistics, &length) ||
		    length != sizeof(statistics)) error = "receive_failed";
		else if (statistics.tp_drops) error = "receive_limit";
		/* A packet queued between the final drain and this observation cutoff
		 * has not been inspected. A successful empty-queue result is unsafe. */
		else if (statistics.tp_packets != received) error = "receive_failed";
	}
	if (!error) {
		now = monotonic_ms();
		if (now < 0) error = "receive_failed";
		else if (now - start >= BUDGET_MS) error = "budget_exceeded";
		else if (transmitted != 2) error = "send_failed";
	}
done:
	close(socket_fd);
	if (error) return unavailable(error);
	printf("{\"schema\":1,\"status\":\"%s\",\"transmitted\":%u,\"claims\":%u}\n",
		claims ? "conflict_observed" : "no_conflict_observed", transmitted, claims);
	return 0;
}
