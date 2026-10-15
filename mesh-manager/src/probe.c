// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MESH_STATE_DIR
#define MESH_STATE_DIR "/etc/mesh-manager"
#endif
#ifndef MESH_CLUSTER_LOCK
#define MESH_CLUSTER_LOCK "/var/run/mesh-manager-cluster.lock"
#endif
#ifndef MESH_STATE_UID
#define MESH_STATE_UID 0
#endif
#define STATE_LIMIT (1024 * 1024)
#define PROBE_LIMIT 512

static int private_stat(int fd, int directory)
{
	struct stat st;
	return !fstat(fd, &st) && st.st_uid == MESH_STATE_UID && !(st.st_mode & 0077) &&
	       (directory ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode) && st.st_nlink == 1);
}

static char *read_private(int directory, const char *name, size_t *length)
{
	int fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	struct stat before, after;
	char *data = NULL, extra;
	size_t used = 0;
	ssize_t n;
	if (fd < 0 || !private_stat(fd, 0) || fstat(fd, &before) ||
	    before.st_size <= 0 || before.st_size > STATE_LIMIT)
		goto done;
	data = malloc((size_t)before.st_size + 1);
	if (!data)
		goto done;
	while (used < (size_t)before.st_size) {
		n = read(fd, data + used, (size_t)before.st_size - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			goto fail;
		used += (size_t)n;
	}
	do { n = read(fd, &extra, 1); } while (n < 0 && errno == EINTR);
	if (n != 0 || fstat(fd, &after) || after.st_size != before.st_size ||
	    after.st_mtim.tv_sec != before.st_mtim.tv_sec || after.st_mtim.tv_nsec != before.st_mtim.tv_nsec ||
	    after.st_ctim.tv_sec != before.st_ctim.tv_sec || after.st_ctim.tv_nsec != before.st_ctim.tv_nsec ||
	    !private_stat(fd, 0))
		goto fail;
	data[used] = 0;
	*length = used;
	goto done;
fail:
	OPENSSL_cleanse(data, used);
	free(data);
	data = NULL;
done:
	if (fd >= 0) close(fd);
	return data;
}

static json_object *parse(const char *data, size_t length)
{
	json_object *value = NULL;
	struct json_tokener *parser = json_tokener_new_ex(64);
	if (!parser)
		return NULL;
	json_tokener_set_flags(parser, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
	value = json_tokener_parse_ex(parser, data, (int)length);
	if (json_tokener_get_error(parser) != json_tokener_success ||
	    json_tokener_get_parse_end(parser) != length || !json_object_is_type(value, json_type_object)) {
		json_object_put(value);
		value = NULL;
	}
	json_tokener_free(parser);
	return value;
}

static json_object *load(int directory, const char *name, const char **error)
{
	size_t length;
	char *data = read_private(directory, name, &length);
	json_object *value;
	if (!data) {
		*error = "storage_error";
		return NULL;
	}
	value = parse(data, length);
	OPENSSL_cleanse(data, length);
	free(data);
	if (!value) *error = "corrupt_state";
	return value;
}

static json_object *field(json_object *object, const char *name)
{
	json_object *value = NULL;
	if (json_object_is_type(object, json_type_object))
		json_object_object_get_ex(object, name, &value);
	return value;
}

static const char *text(json_object *object, const char *name)
{
	json_object *value = field(object, name);
	const char *s = json_object_is_type(value, json_type_string) ? json_object_get_string(value) : NULL;
	return s && strlen(s) == (size_t)json_object_get_string_len(value) ? s : NULL;
}

static int hex(const char *s, size_t length)
{
	if (!s || strlen(s) != length)
		return 0;
	for (size_t i = 0; i < length; i++)
		if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
			return 0;
	return 1;
}

static int number(json_object *object, const char *name, int expected)
{
	json_object *value = field(object, name);
	return json_object_is_type(value, json_type_int) && json_object_get_int64(value) == expected;
}

static int no_password(char *buffer, int size, int writing, void *data)
{
	(void)buffer; (void)size; (void)writing; (void)data;
	return 0;
}

static int key_matches(int directory, const char *id, const char *fingerprint)
{
	size_t length;
	char *pem = read_private(directory, "device.key", &length), digest[65];
	unsigned char hash[EVP_MAX_MD_SIZE], *der = NULL;
	unsigned int hash_length = 0;
	BIO *bio = pem ? BIO_new_mem_buf(pem, (int)length) : NULL;
	EVP_PKEY *key = bio ? PEM_read_bio_PrivateKey(bio, NULL, no_password, NULL) : NULL;
	int bytes = key ? i2d_PUBKEY(key, &der) : -1, result = 0;
	if (bytes > 0 && EVP_Digest(der, (size_t)bytes, hash, &hash_length, EVP_sha256(), NULL) && hash_length == 32) {
		for (size_t i = 0; i < 32; i++) sprintf(digest + i * 2, "%02x", hash[i]);
		result = !strcmp(digest, fingerprint) && !strncmp(digest, id, 32);
	}
	EVP_PKEY_free(key);
	BIO_free(bio);
	OPENSSL_free(der);
	if (pem) { OPENSSL_cleanse(pem, length); free(pem); }
	return result;
}

static int certificate_matches(int directory, const char *fingerprint)
{
	size_t length;
	char *pem = read_private(directory, "device.crt", &length), digest[65];
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int size = 0;
	BIO *bio = pem ? BIO_new_mem_buf(pem, (int)length) : NULL;
	X509 *cert = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
	int result = 0;
	if (cert && X509_digest(cert, EVP_sha256(), hash, &size) && size == 32) {
		for (size_t i = 0; i < 32; i++) sprintf(digest + i * 2, "%02x", hash[i]);
		result = hex(fingerprint, 64) && !strcmp(digest, fingerprint);
	}
	X509_free(cert); BIO_free(bio); free(pem);
	return result;
}

/* The retained data gateway can authenticate paths after controller migration.
 * Its exact new-controller binding owns the roster; it holds no CA signing key.
 * This exception permits only the native four-field read-only probe below. */
static int anchored_gateway(int directory, json_object *identity, json_object *cluster, const char *id)
{
	json_object *anchor = field(identity, "anchor"), *binding = field(identity, "binding");
	const char *gateway = text(anchor, "gateway"), *address = text(anchor, "address");
	struct in_addr ipv4;
	struct stat st;
	if (!json_object_is_type(anchor, json_type_object) || json_object_object_length(anchor) != 5 ||
	    !text(anchor, "id") || strcmp(text(anchor, "id"), id) || !address ||
	    inet_pton(AF_INET, address, &ipv4) != 1 || !text(anchor, "control_address") ||
	    strcmp(text(anchor, "control_address"), "169.254.254.1") ||
	    !gateway || (strcmp(gateway, "router") && strcmp(gateway, "bridge")) ||
	    !certificate_matches(directory, text(anchor, "certificate"))) return 0;
	uint32_t ip = ntohl(ipv4.s_addr);
	if ((ip >> 24) != 10 && (ip >> 20) != 0xac1 && (ip >> 16) != 0xc0a8) return 0;
	if (!json_object_is_type(binding, json_type_object) ||
	    !json_object_equal(binding, field(cluster, "roster_authority")) ||
	    !hex(text(binding, "controller_id"), 32) || !strcmp(text(binding, "controller_id"), id) ||
	    !hex(text(binding, "controller_certificate"), 64) || !hex(text(binding, "ca_fingerprint"), 64) ||
	    !text(binding, "network_id") || !text(identity, "network_id") ||
	    strcmp(text(binding, "network_id"), text(identity, "network_id")) ||
	    !json_object_is_type(field(identity, "authority_epoch"), json_type_int) ||
	    json_object_get_int64(field(identity, "authority_epoch")) < 2 ||
	    !json_object_equal(field(identity, "authority_epoch"), field(binding, "epoch"))) return 0;
	if (!fstatat(directory, "network-ca.key", &st, AT_SYMLINK_NOFOLLOW) || errno != ENOENT) return 0;
	return 1;
}

/* Called only after TLS client verification and reception of a probe frame.
 * No state writes, subprocesses, cached authorization or business dispatch here. */
int mesh_probe(const char *peer, const char *controller, const char *certificate, unsigned char *buffer, size_t *length, size_t capacity)
{
	const char *error = "invalid_request", *id = NULL, *network = NULL, *nonce = NULL, *fingerprint;
	json_object *request = NULL, *identity = NULL, *cluster = NULL, *members, *member, *authorized;
	int lock = -1, directory = -1, written;
	if (!hex(peer, 32) || !hex(controller, 32) || !hex(certificate, 64) || !*length || *length > PROBE_LIMIT ||
	    !(request = parse((const char *)buffer, *length)))
		goto done;
	error = "storage_error";
	lock = open(MESH_CLUSTER_LOCK, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (lock < 0 || !private_stat(lock, 0))
		goto done;
	if (flock(lock, LOCK_SH | LOCK_NB)) {
		if (errno == EWOULDBLOCK || errno == EAGAIN) error = "busy";
		goto done;
	}
	directory = open(MESH_STATE_DIR, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY);
	if (directory < 0 || !private_stat(directory, 1) ||
	    !(identity = load(directory, "identity.json", &error)) ||
	    !(cluster = load(directory, "cluster.json", &error)))
		goto done;
	error = "identity_error";
	id = text(identity, "id"); fingerprint = text(identity, "fingerprint");
	if (!number(identity, "schema", 1) || !hex(id, 32) || strcmp(id, controller) || !hex(fingerprint, 64) ||
	    !key_matches(directory, id, fingerprint))
		goto done;
	error = "not_controller";
	if (!text(identity, "role") || (strcmp(text(identity, "role"), "root") &&
	    (strcmp(text(identity, "role"), "ap") || !anchored_gateway(directory, identity, cluster, id))))
		goto done;
	error = "corrupt_state";
	network = text(identity, "network_id"); members = field(cluster, "members");
	if (!hex(network, 32) || !number(cluster, "schema", 1) ||
	    !json_object_is_type(members, json_type_object) || json_object_object_length(members) > 64 ||
	    !json_object_is_type(field(cluster, "requests"), json_type_object) ||
	    json_object_object_length(field(cluster, "requests")) > 64 ||
	    !json_object_is_type(field(cluster, "invitations"), json_type_array) ||
	    json_object_array_length(field(cluster, "invitations")) > 16 ||
	    !json_object_is_type(field(cluster, "history"), json_type_array) ||
	    !json_object_is_type(field(cluster, "version"), json_type_int))
		goto done;
	error = "not_authorized";
	member = field(members, peer); authorized = field(member, "authorized");
	if (!json_object_is_type(authorized, json_type_boolean) || !json_object_get_boolean(authorized) ||
	    !text(member, "certificate") || strcmp(text(member, "certificate"), certificate))
		goto done;
	error = "invalid_request";
	nonce = text(request, "nonce");
	if (json_object_object_length(request) != 4 || !number(request, "protocol", 1) ||
	    !text(request, "action") || strcmp(text(request, "action"), "probe") ||
	    !text(request, "network_id") || strcmp(text(request, "network_id"), network) || !hex(nonce, 32))
		goto done;
	error = NULL;
done:
	if (error)
		written = snprintf((char *)buffer, capacity,
			"{\"ok\":false,\"error\":{\"code\":\"%s\",\"message\":\"Mesh peer request rejected\"}}", error);
	else
		written = snprintf((char *)buffer, capacity,
			"{\"ok\":true,\"data\":{\"controller_id\":\"%s\",\"network_id\":\"%s\",\"nonce\":\"%s\"}}", id, network, nonce);
	json_object_put(request); json_object_put(identity); json_object_put(cluster);
	if (directory >= 0) close(directory);
	if (lock >= 0) close(lock);
	if (written < 0 || (size_t)written >= capacity)
		return 0;
	*length = (size_t)written;
	return 1;
}
