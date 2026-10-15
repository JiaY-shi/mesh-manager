// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PEER_WORKER
#define PEER_WORKER "/usr/libexec/mesh-manager-peer"
#endif
#define MAX_FRAME 65536
#define MAX_CLIENTS 4
#define FRAME_PROBE UINT32_C(0x80000000)
#define INITIAL_SECONDS 8
#define PROBE_SECONDS 3
#define API_SECONDS 15
#define API_WORKER_SECONDS 12
#define CONTROL_DEVICE "br-mm-ctl"
#define CONTROL_ADDRESS UINT32_C(0xa9fefe01)

int mesh_probe(const char *peer, const char *controller, const char *certificate, unsigned char *buffer, size_t *length, size_t capacity);

static int64_t milliseconds(void)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return -1;
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int deadline_timer(int64_t deadline)
{
	int64_t now = milliseconds(), remaining = deadline - now;
	struct itimerval timer = { 0 };
	if (now < 0 || remaining <= 0)
		return 0;
	timer.it_value.tv_sec = (time_t)(remaining / 1000);
	timer.it_value.tv_usec = (suseconds_t)(remaining % 1000) * 1000;
	return setitimer(ITIMER_REAL, &timer, NULL) == 0;
}

static int valid_identity(const char *id)
{
	if (strlen(id) != 32)
		return 0;
	for (size_t i = 0; i < 32; i++)
		if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f')))
			return 0;
	return 1;
}

static int peer_identity(SSL *ssl, char out[33], char certificate[65])
{
	X509 *peer = SSL_get1_peer_certificate(ssl);
	int n, valid;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int size = 0;
	if (!peer)
		return 0;
	n = X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, out, 33);
	valid = X509_digest(peer, EVP_sha256(), digest, &size) == 1 && size == 32;
	if (valid) for (unsigned int i = 0; i < size; i++) snprintf(certificate + 2 * i, 3, "%02x", digest[i]);
	X509_free(peer);
	return valid && n == 32 && valid_identity(out) && SSL_get_verify_result(ssl) == X509_V_OK;
}

static int transfer(SSL *ssl, unsigned char *data, size_t length, int write_data)
{
	while (length) {
		int n = write_data ? SSL_write(ssl, data, (int)length) : SSL_read(ssl, data, (int)length);
		if (n <= 0)
			return 0;
		data += n;
		length -= (size_t)n;
	}
	return 1;
}

static int frame(SSL *ssl, unsigned char *data, size_t *size, int send_data, int *probe, int64_t probe_deadline)
{
	uint32_t header = send_data ? htonl((uint32_t)*size | (probe && *probe ? FRAME_PROBE : 0)) : 0;
	if (!transfer(ssl, (unsigned char *)&header, sizeof(header), send_data))
		return 0;
	if (!send_data) {
		header = ntohl(header);
		if (!probe && (header & FRAME_PROBE))
			return 0;
		if (probe) *probe = (header & FRAME_PROBE) != 0;
		if (probe && *probe && probe_deadline && !deadline_timer(probe_deadline))
			return 0;
		*size = header & ~FRAME_PROBE;
	}
	if (!*size || *size > MAX_FRAME)
		return 0;
	return transfer(ssl, data, *size, send_data);
}

static int address(const char *host, const char *port, struct sockaddr_in *out)
{
	char *end;
	long number = strtol(port, &end, 10);
	uint32_t ip;
	memset(out, 0, sizeof(*out));
	if (!*port || *end || number < 1024 || number > 65535 || inet_pton(AF_INET, host, &out->sin_addr) != 1)
		return 0;
	ip = ntohl(out->sin_addr.s_addr);
	/* LAN-only control plane; never listen on a wildcard or public WAN address. */
	if ((ip & 0xff000000) != 0x0a000000 && (ip & 0xfff00000) != 0xac100000 &&
	    (ip & 0xffff0000) != 0xc0a80000 && (ip & 0xff000000) != 0x7f000000 &&
	    (ip & 0xffff0000) != 0xa9fe0000)
		return 0;
	out->sin_family = AF_INET;
	out->sin_port = htons((uint16_t)number);
	return 1;
}

static SSL_CTX *context(const char *ca, const char *cert, const char *key, int server, int enrollment)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_method());
	if (!ctx)
		return NULL;
	if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
	    SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1)
		goto fail;
	SSL_CTX_set_verify(ctx, server && enrollment ? SSL_VERIFY_NONE :
	                   SSL_VERIFY_PEER | (server ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0), NULL);
	SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
	if (strcmp(cert, "-")) {
		if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1 ||
		    SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1 ||
		    SSL_CTX_check_private_key(ctx) != 1)
			goto fail;
	} else if (server || strcmp(key, "-")) {
		goto fail;
	}
	return ctx;
fail:
	SSL_CTX_free(ctx);
	return NULL;
}

static int write_all(int fd, const unsigned char *data, size_t size)
{
	while (size) {
		ssize_t n = write(fd, data, size);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return 0;
		data += n;
		size -= (size_t)n;
	}
	return 1;
}

static int worker(const char *identity, const char *mode, const char *source, const char *destination, const char *certificate, unsigned char *data, size_t *size, int64_t deadline)
{
	int input[2], output[2], status, ok = 0;
	pid_t child, parent = getpid();
	size_t used = 0;
	ssize_t n;
	if (pipe2(input, O_CLOEXEC))
		return 0;
	if (pipe2(output, O_CLOEXEC)) {
		close(input[0]); close(input[1]);
		return 0;
	}
	child = fork();
	if (child == 0) {
		// The transport deadline must also stop a worker after a delayed handshake.
		int64_t now = milliseconds(), own_deadline = now + API_WORKER_SECONDS * 1000;
		if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent || now < 0 ||
		    !deadline_timer(own_deadline < deadline ? own_deadline : deadline))
			_exit(127);
		dup2(input[0], STDIN_FILENO); dup2(output[1], STDOUT_FILENO);
		close(input[0]); close(input[1]); close(output[0]); close(output[1]);
		execl(PEER_WORKER, PEER_WORKER, identity, mode, source, "api", destination, certificate, (char *)NULL);
		_exit(127);
	}
	close(input[0]); close(output[1]);
	if (child < 0) {
		close(input[1]); close(output[0]);
		return 0;
	}
	if (write_all(input[1], data, *size)) {
		close(input[1]); input[1] = -1;
		while (used < MAX_FRAME && (n = read(output[0], data + used, MAX_FRAME - used)) > 0)
			used += (size_t)n;
		if (used && used < MAX_FRAME)
			ok = 1;
	}
	if (input[1] >= 0) close(input[1]);
	close(output[0]);
	if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status))
		ok = 0;
	*size = used;
	return ok;
}

static void handle(SSL_CTX *ctx, int fd, int enrollment, unsigned int control_index)
{
	int64_t started = milliseconds(), deadline;
	SSL *ssl = SSL_new(ctx);
	unsigned char buffer[MAX_FRAME];
	char identity[33] = "";
	char certificate[65] = "";
	char controller[33] = "";
	char source[INET_ADDRSTRLEN] = "";
	char destination[INET_ADDRSTRLEN] = "";
	struct sockaddr_in peer, local;
	socklen_t peer_size = sizeof(peer);
	socklen_t local_size = sizeof(local);
	size_t size;
	int probe = 0;
	if (!ssl || started < 0 || !deadline_timer(started + INITIAL_SECONDS * 1000))
		goto done;
	SSL_set_fd(ssl, fd);
	if (SSL_accept(ssl) != 1 || (!enrollment && !peer_identity(ssl, identity, certificate)))
		goto done;
	X509 *own = SSL_get_certificate(ssl);
	if (!own || X509_NAME_get_text_by_NID(X509_get_subject_name(own), NID_commonName, controller, sizeof(controller)) != 32 ||
	    !valid_identity(controller))
		goto done;
	if (getpeername(fd, (struct sockaddr *)&peer, &peer_size) || peer.sin_family != AF_INET ||
	    !inet_ntop(AF_INET, &peer.sin_addr, source, sizeof(source)))
		goto done;
	if (getsockname(fd, (struct sockaddr *)&local, &local_size) || local.sin_family != AF_INET ||
	    !inet_ntop(AF_INET, &local.sin_addr, destination, sizeof(destination)))
		goto done;
	if (frame(ssl, buffer, &size, 0, &probe, started + PROBE_SECONDS * 1000) && !(enrollment && probe)) {
		if (control_index && if_nametoindex(CONTROL_DEVICE) != control_index)
			goto done;
		/* Routing through a standby interface does not make a queued business request a probe. */
		deadline = started + (probe ? PROBE_SECONDS : API_SECONDS) * 1000;
		if (deadline_timer(deadline) &&
		    (probe ? mesh_probe(identity, controller, certificate, buffer, &size, sizeof(buffer)) :
		     worker(identity, enrollment ? "enroll" : "node", source, destination, certificate, buffer, &size, deadline)))
			frame(ssl, buffer, &size, 1, NULL, 0);
	}
done:
	SSL_free(ssl);
	close(fd);
}

static int listener(const struct sockaddr_in *addr, unsigned int control_index)
{
	int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0), yes = 1;
	if (sock < 0)
		return -1;
	/* Keep the validated explicit address bound while netifd brings LAN or the control VLAN up. */
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) ||
	    setsockopt(sock, IPPROTO_IP, IP_FREEBIND, &yes, sizeof(yes)) ||
	    (control_index && (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, CONTROL_DEVICE, sizeof(CONTROL_DEVICE)) ||
	                       if_nametoindex(CONTROL_DEVICE) != control_index)) ||
	    bind(sock, (const struct sockaddr *)addr, sizeof(*addr)) || listen(sock, 8)) {
		close(sock);
		return -1;
	}
	return sock;
}

static int serve(SSL_CTX *ctx, const struct sockaddr_in *addr, int enrollment)
{
	int isolated = !enrollment && ntohl(addr->sin_addr.s_addr) == CONTROL_ADDRESS;
	int sock = isolated ? -1 : listener(addr, 0);
	unsigned int control_index = 0;
	int64_t next_interface_check = 0;
	pid_t children[MAX_CLIENTS] = { 0 };
	if (!isolated && sock < 0)
		return 1;
	for (;;) {
		int slot = -1;
		for (int i = 0; i < MAX_CLIENTS; i++) {
			if (children[i] && waitpid(children[i], NULL, WNOHANG) == children[i])
				children[i] = 0;
			if (!children[i]) slot = i;
		}
		if (isolated) {
			int64_t now = milliseconds();
			if (now < 0) { if (sock >= 0) close(sock); return 1; }
			if (now >= next_interface_check) {
				unsigned int current = if_nametoindex(CONTROL_DEVICE);
				if (current != control_index && sock >= 0) { close(sock); sock = -1; }
				control_index = current;
				/* Startup and netifd recreation may temporarily remove the bridge.
				 * Stay supervised and idle; never expose an unbound fallback. */
				if (control_index && sock < 0) sock = listener(addr, control_index);
				next_interface_check = now + 1000;
			}
		}
		struct pollfd ready = { .fd = sock, .events = POLLIN };
		if (sock < 0) { poll(NULL, 0, 1000); continue; }
		if (poll(&ready, 1, 250) <= 0)
			continue;
		int fd = accept4(sock, NULL, NULL, SOCK_CLOEXEC);
		if (fd < 0)
			continue;
		if (isolated && (!control_index || if_nametoindex(CONTROL_DEVICE) != control_index)) {
			close(fd); close(sock); sock = -1; next_interface_check = 0; continue;
		}
		if (slot < 0) { close(fd); continue; }
		children[slot] = fork();
		if (!children[slot]) {
			close(sock);
			handle(ctx, fd, enrollment, control_index);
			_exit(0);
		}
		if (children[slot] < 0) children[slot] = 0;
		close(fd);
	}
}

static int client(SSL_CTX *ctx, const struct sockaddr_in *addr, const char *expected, const char *device, const char *pin, int probe)
{
	int sock = -1, rc = 1;
	SSL *ssl = NULL;
	unsigned char buffer[MAX_FRAME];
	char identity[33];
	size_t size = 0;
	ssize_t n;
	alarm(probe ? PROBE_SECONDS : API_SECONDS);
	while (size < MAX_FRAME && (n = read(STDIN_FILENO, buffer + size, MAX_FRAME - size)) > 0)
		size += (size_t)n;
	if (!size || size >= MAX_FRAME || !valid_identity(expected))
		goto done;
	sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0)
		goto done;
	/* Bind before routing: a standby probe must never escape through the active path. */
	if (device && (!*device || strlen(device) >= IFNAMSIZ || !if_nametoindex(device) ||
	    setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device) + 1)))
		goto done;
	if (connect(sock, (const struct sockaddr *)addr, sizeof(*addr)))
		goto done;
	ssl = SSL_new(ctx);
	if (!ssl)
		goto done;
	SSL_set_fd(ssl, sock);
	char certificate[65];
	if (SSL_connect(ssl) != 1 || !peer_identity(ssl, identity, certificate) || strcmp(identity, expected) ||
	    (pin && strcmp(certificate, pin)))
		goto done;
	if (frame(ssl, buffer, &size, 1, &probe, 0) && frame(ssl, buffer, &size, 0, NULL, 0) && write_all(STDOUT_FILENO, buffer, size))
		rc = 0;
done:
	SSL_free(ssl);
	if (sock >= 0) close(sock);
	return rc;
}

static int inspect(SSL_CTX *ctx, const struct sockaddr_in *addr, const char *device, const char *nonce)
{
	/* No credential is sent here. The caller pins the returned CA before joining. */
	char request[128];
	int length = nonce ? snprintf(request, sizeof(request),
		"{\"protocol\":1,\"action\":\"info\",\"clock_nonce\":\"%s\"}", nonce) :
		snprintf(request, sizeof(request), "{\"protocol\":1,\"action\":\"info\"}");
	if (length < 0 || (size_t)length >= sizeof(request))
		return 1;
	int sock = -1, rc = 1;
	SSL *ssl = NULL;
	unsigned char buffer[MAX_FRAME];
	size_t size = (size_t)length;
	alarm(8);
	sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0)
		return rc;
	if (device && (!*device || strlen(device) >= IFNAMSIZ || !if_nametoindex(device) ||
	    setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device) + 1)))
		goto done;
	if (connect(sock, (const struct sockaddr *)addr, sizeof(*addr)))
		goto done;
	ssl = SSL_new(ctx);
	if (!ssl)
		goto done;
	SSL_set_fd(ssl, sock);
	memcpy(buffer, request, size);
	if (SSL_connect(ssl) == 1 && frame(ssl, buffer, &size, 1, NULL, 0) &&
	    frame(ssl, buffer, &size, 0, NULL, 0) && write_all(STDOUT_FILENO, buffer, size))
		rc = 0;
done:
	SSL_free(ssl);
	close(sock);
	return rc;
}

int main(int argc, char **argv)
{
	struct sockaddr_in addr;
	SSL_CTX *ctx;
	int rc, server, enrollment;
	signal(SIGPIPE, SIG_IGN);
	int clock_inspect = argc >= 2 && !strcmp(argv[1], "inspect-clock");
	if ((((argc == 4 || argc == 5) && !strcmp(argv[1], "inspect")) ||
	     (clock_inspect && (argc == 5 || argc == 6) && valid_identity(argv[4]))) &&
	    address(argv[2], argv[3], &addr)) {
		ctx = SSL_CTX_new(TLS_client_method());
		if (!ctx)
			return 3;
		if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
			SSL_CTX_free(ctx);
			return 3;
		}
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
		SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
		rc = inspect(ctx, &addr, clock_inspect ? (argc == 6 ? argv[5] : NULL) :
			(argc == 5 ? argv[4] : NULL), clock_inspect ? argv[4] : NULL);
		SSL_CTX_free(ctx);
		return rc;
	}
	if ((argc != 8 && argc != 9 && argc != 10) || (strcmp(argv[1], "serve") && strcmp(argv[1], "client") && strcmp(argv[1], "probe")) || !address(argv[2], argv[3], &addr))
		return 2;
	server = !strcmp(argv[1], "serve");
	if (server && argc != 8)
		return 2;
	if (argc == 10) {
		if (strlen(argv[9]) != 64 || strspn(argv[9], "0123456789abcdef") != 64) return 2;
	}
	enrollment = server && !strcmp(argv[7], "enroll");
	if (server && strcmp(argv[7], "node") && !enrollment)
		return 2;
	ctx = context(argv[4], argv[5], argv[6], server, enrollment);
	if (!ctx)
		return 3;
	rc = server ? serve(ctx, &addr, enrollment) : client(ctx, &addr, argv[7],
		argc >= 9 && strcmp(argv[8], "-") ? argv[8] : NULL, argc == 10 ? argv[9] : NULL, !strcmp(argv[1], "probe"));
	SSL_CTX_free(ctx);
	return rc;
}
