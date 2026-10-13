// SPDX-License-Identifier: GPL-2.0-only
/* One fixed root NS question to an already sampled IPv4 DNS candidate. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define BUDGET_MS 1250
#define PACKET_LIMIT 512
#define RECEIVE_LIMIT 32
#define NAME_STEPS 256
#define RR_LIMIT 64
#define QUERY_LENGTH 17

struct reply { const char *status; int rcode; };
struct names { unsigned char boundary[PACKET_LIMIT]; };

static int64_t monotonic_ms(void)
{
	struct timespec value;
	if (clock_gettime(CLOCK_MONOTONIC, &value)) return -1;
	return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static int output(const char *status, int rcode, int64_t started, unsigned int transmitted,
		  unsigned int received, int exit_code)
{
	int64_t ended = monotonic_ms(), elapsed = started >= 0 && ended >= started ? ended - started : -1;
	/* Recheck at publication as well: scheduling between the caller's final
 * deadline check and here cannot turn an expired reply into a timely success. */
	if (rcode >= 0 && (elapsed < 0 || elapsed >= BUDGET_MS)) {
		status = elapsed < 0 ? "clock_unavailable" : "budget_exceeded";
		rcode = -1; exit_code = 1;
	}
	/* A paused process can exceed its deadline. Report the elapsed value honestly. */
	if (elapsed > 60000) elapsed = 60000;
	printf("{\"schema\":1,\"status\":\"%s\",\"rcode\":", status);
	if (rcode < 0) fputs("null", stdout); else printf("%d", rcode);
	if (elapsed < 0) fputs(",\"elapsed_ms\":null", stdout);
	else printf(",\"elapsed_ms\":%lld", (long long)elapsed);
	printf(",\"transmitted\":%u,\"received\":%u}\n", transmitted, received);
	return exit_code;
}

static bool valid_target(int argc, char **argv, struct in_addr *address)
{
	char canonical[INET_ADDRSTRLEN];
	if (argc != 2 || inet_pton(AF_INET, argv[1], address) != 1 ||
	    !inet_ntop(AF_INET, address, canonical, sizeof(canonical)) || strcmp(canonical, argv[1])) return false;
	uint32_t host = ntohl(address->s_addr);
	return (host >> 24) != 0 && (host >> 24) != 127 && (host >> 24) < 224;
}

static uint16_t word(const unsigned char *data) { return (uint16_t)data[0] << 8 | data[1]; }

/* Track consumed wire bytes independently from expansion. Backward-only pointers
 * plus a step/expanded-size cap reject cycles, forward pointers and huge labels. */
static bool dns_name(const unsigned char *data, size_t length, size_t start, struct names *names,
		     size_t *consumed, bool *root)
{
	size_t position = start, wire = 0, expanded = 1;
	bool jumped = false, empty = true;
	for (unsigned int step = 0; step < NAME_STEPS; step++) {
		if (position >= length) return false;
		unsigned char label = data[position];
		if ((label & 0xc0) == 0xc0) {
			if (position + 1 >= length) return false;
			size_t target = ((size_t)(label & 0x3f) << 8) | data[position + 1];
			if (target < 12 || target >= position || !names->boundary[target]) return false;
			names->boundary[position] = 1;
			if (!jumped) wire += 2;
			jumped = true; position = target; continue;
		}
		if (label & 0xc0) return false;
		names->boundary[position] = 1;
		position++;
		if (!jumped) wire++;
		if (!label) { *consumed = wire; *root = empty; return true; }
		if (position + label > length || expanded + label + 1 > 255) return false;
		expanded += label + 1; empty = false;
		if (!jumped) wire += label;
		position += label;
	}
	return false;
}

static bool name_rdata(const unsigned char *data, size_t length, size_t start, size_t size, struct names *names,
		       size_t prefix, bool require_name)
{
	size_t wire;
	bool root;
	return size > prefix && dns_name(data, length, start + prefix, names, &wire, &root) &&
	       wire + prefix == size && (!require_name || !root);
}

static bool rr_data(const unsigned char *data, size_t length, size_t start, size_t size,
		    uint16_t type, uint16_t klass, struct names *names)
{
	if (type == 41) { /* EDNS: the unsolicited option data must still be framed. */
		if (klass < 512) return false;
		size_t position = start;
		while (position < start + size) {
			if (start + size - position < 4) return false;
			size_t option = word(data + position + 2);
			position += 4;
			if (option > start + size - position) return false;
			position += option;
		}
		return true;
	}
	if (klass != 1) return false;
	if (type == 1) return size == 4;
	if (type == 28) return size == 16;
	if (type == 2 || type == 5 || type == 12) return name_rdata(data,length,start,size,names,0,true);
	if (type == 15) return name_rdata(data,length,start,size,names,2,true);
	if (type == 33) return name_rdata(data,length,start,size,names,6,false);
	if (type == 6) {
		size_t first, second; bool root;
		return size >= 22 && dns_name(data,length,start,names,&first,&root) && first < size &&
		       dns_name(data,length,start+first,names,&second,&root) && first + second + 20 == size;
	}
	if (type == 16) {
		size_t position = start;
		while (position < start + size) {
			size_t part = data[position++];
			if (part > start + size - position) return false;
			position += part;
		}
		return size > 0;
	}
	/* Unknown RDATA is intentionally opaque under RFC 3597. Its RR framing
 * remains validated; it can never substitute for the expected root NS answer. */
	return type != 0;
}

static bool parse_reply(const unsigned char *data, size_t length, uint16_t id, struct reply *reply)
{
	if (length < QUERY_LENGTH || length > PACKET_LIMIT || word(data) != id) return false;
	uint16_t flags = word(data + 2), answer_count = word(data + 6),
		 authority_count = word(data + 8), additional_count = word(data + 10);
	if (!(flags & 0x8000) || flags & 0x7840 || word(data + 4) != 1 ||
	    (unsigned int)answer_count + authority_count + additional_count > RR_LIMIT) return false;
	size_t position = 12, wire; bool root;
	struct names names = { { 0 } };
	if (!dns_name(data,length,position,&names,&wire,&root) || !root || wire > length - position ||
	    length - position - wire < 4 || word(data + position + wire) != 2 ||
	    word(data + position + wire + 2) != 1) return false;
	position += wire + 4;
	reply->rcode = flags & 15;
	if (flags & 0x0200) { reply->status = "truncated_requires_tcp"; return true; }
	unsigned int root_ns = 0, total = (unsigned int)answer_count + authority_count + additional_count;
	bool have_opt = false;
	for (unsigned int record = 0; record < total; record++) {
		if (!dns_name(data,length,position,&names,&wire,&root) || wire > length - position ||
		    length - position - wire < 10) return false;
		position += wire;
		uint16_t type = word(data + position), klass = word(data + position + 2), size = word(data + position + 8);
		if (type == 41) {
			/* No query EDNS was sent. Reject extended RCODES/version/Z bits;
 * accepting them as ordinary NOERROR would give a false positive. */
			if (!root || have_opt || record < (unsigned int)answer_count + authority_count ||
			    word(data + position + 4) || (word(data + position + 6) & 0x7fff)) return false;
			have_opt = true;
		}
		position += 10;
		if (size > length - position || !rr_data(data,length,position,size,type,klass,&names)) return false;
		if (record < answer_count && type == 2 && klass == 1 && root) root_ns++;
		position += size;
	}
	if (position != length) return false;
	static const char *codes[] = { "empty_answer", "formerr", "servfail", "nxdomain", "notimp", "refused" };
	reply->status = reply->rcode == 0 && root_ns ? "answered" :
		       reply->rcode < 6 ? codes[reply->rcode] : "other_rcode";
	return true;
}

static bool query_id(uint16_t *id, int64_t deadline)
{
	ssize_t size;
	do {
		int64_t current = monotonic_ms();
		if (current < 0 || current >= deadline) return false;
		size = getrandom(id,sizeof(*id),GRND_NONBLOCK);
	} while (size < 0 && errno == EINTR);
	return size == (ssize_t)sizeof(*id);
}

int main(int argc, char **argv)
{
	int64_t started = monotonic_ms(), deadline = started + BUDGET_MS;
	struct in_addr address;
	if (started < 0) return output("clock_unavailable",-1,started,0,0,1);
	if (!valid_target(argc,argv,&address)) return output("invalid_target",-1,started,0,0,1);
	uint16_t id;
	if (!query_id(&id,deadline)) return output("entropy_unavailable",-1,started,0,0,1);
	unsigned char query[QUERY_LENGTH] = { 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1 };
	query[0] = id >> 8; query[1] = id & 255;
	int fd = socket(AF_INET,SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,0);
	if (fd < 0) return output("socket_unavailable",-1,started,0,0,1);
	struct sockaddr_in remote = { .sin_family = AF_INET, .sin_port = htons(53), .sin_addr = address };
	if (connect(fd,(struct sockaddr *)&remote,sizeof(remote))) {
		close(fd); return output("network_unreachable",-1,started,0,0,0);
	}
	/* All setup time belongs to the same budget; do not send after a long pause. */
	int64_t current = monotonic_ms();
	if (current < 0 || current >= deadline) {
		close(fd); return output("budget_exceeded",-1,started,0,0,1);
	}
	ssize_t sent = send(fd,query,sizeof(query),MSG_NOSIGNAL);
	if (sent != (ssize_t)sizeof(query)) {
		close(fd); return output("send_failed",-1,started,0,0,1);
	}
	unsigned int received = 0;
	struct pollfd channel = { .fd = fd, .events = POLLIN };
	while (received < RECEIVE_LIMIT) {
		current = monotonic_ms();
		if (current < 0) { close(fd); return output("clock_unavailable",-1,started,1,received,1); }
		if (current >= deadline) break;
		int ready = poll(&channel,1,(int)(deadline-current));
		if (ready < 0 && errno == EINTR) continue;
		if (ready < 0) { close(fd); return output("receive_failed",-1,started,1,received,1); }
		if (!ready) break;
		current = monotonic_ms();
		if (current < 0) { close(fd); return output("clock_unavailable",-1,started,1,received,1); }
		if (current >= deadline) break;
		unsigned char data[PACKET_LIMIT];
		struct iovec vector = { .iov_base = data, .iov_len = sizeof(data) };
		struct msghdr message = { .msg_iov = &vector, .msg_iovlen = 1 };
		ssize_t size = recvmsg(fd,&message,MSG_DONTWAIT);
		if (size < 0 && (errno == EAGAIN || errno == EINTR)) continue;
		if (size < 0) {
			int saved = errno; close(fd);
			return output(saved == ECONNREFUSED || saved == EHOSTUNREACH || saved == ENETUNREACH ?
				      "network_unreachable" : "receive_failed",-1,started,1,received,
				      saved == ECONNREFUSED || saved == EHOSTUNREACH || saved == ENETUNREACH ? 0 : 1);
		}
		received++;
		struct reply reply;
		if (!(message.msg_flags & MSG_TRUNC) && parse_reply(data,(size_t)size,id,&reply)) {
			current = monotonic_ms();
			if (current < 0) { close(fd); return output("clock_unavailable",-1,started,1,received,1); }
			if (current >= deadline) break;
			close(fd); return output(reply.status,reply.rcode,started,1,received,0);
		}
	}
	close(fd);
	return output(received == RECEIVE_LIMIT ? "receive_limit" : received ? "invalid_reply" : "no_reply",
		      -1,started,1,received,0);
}
