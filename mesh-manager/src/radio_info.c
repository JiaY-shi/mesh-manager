// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
/* libiwinfo's utility header has redundant const return qualifiers. Keep our
 * strict build flags without changing the upstream package's public headers. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-qualifiers"
#include <iwinfo.h>
#pragma GCC diagnostic pop
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

#ifndef MESH_RADIO_SYSFS
#define MESH_RADIO_SYSFS "/sys/class"
#endif
#define CHANNEL_LIMIT 256
#define POWER_LIMIT 64
#define OUTPUT_LIMIT 65536
#define BUDGET_MS 2000

struct binding {
	char phy[64];
	unsigned int phy_index, ifindex, flags;
	dev_t device;
	ino_t inode;
	dev_t net_device;
	ino_t net_inode;
};
struct channel {
	unsigned int band, channel, frequency, flags;
	bool restricted;
};
struct axis { unsigned int count; bool invalid, truncated, failed; };
static char output[OUTPUT_LIMIT];
static size_t output_length;
static bool output_failed;
static int64_t started;
static const char *fatal;
static const char *issues[32];
static unsigned int issue_count;
static const char *flag_names[] = { "no_10mhz", "no_20mhz", "no_ht40+", "no_ht40-",
	"no_80mhz", "no_160mhz", "no_he", "no_ir", "indoor_only" };

static bool budget(void)
{
	struct timespec now = {0};
	if (clock_gettime(CLOCK_MONOTONIC, &now)) { fatal = "read_failed"; return false; }
	if ((int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 - started >= BUDGET_MS) {
		fatal = "budget_exceeded"; return false;
	}
	return true;
}
static void issue(const char *code)
{
	for (unsigned int i = 0; i < issue_count; i++) if (!strcmp(issues[i], code)) return;
	if (issue_count < sizeof(issues)/sizeof(issues[0])) issues[issue_count++] = code;
}
static bool token(const char *value, size_t limit, bool dots)
{
	size_t length = strnlen(value, limit + 1);
	if (!length || length > limit || value[0] == '.' || value[0] == '-') return false;
	for (size_t i = 0; i < length; i++) {
		unsigned char c = (unsigned char)value[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		      c == '_' || c == '-' || (dots && c == '.'))) return false;
	}
	return true;
}
static bool read_number(const char *path, unsigned int *value)
{
	char text[32], *end;
	FILE *file = fopen(path, "re");
	if (!file) return false;
	size_t length = fread(text, 1, sizeof(text) - 1, file);
	bool valid = !ferror(file) && feof(file);
	fclose(file);
	text[length] = 0;
	if (!valid || !length || text[0] == '-') return false;
	errno = 0;
	unsigned long number = strtoul(text, &end, 0);
	if (end == text) return false;
	while (*end == ' ' || *end == '\n' || *end == '\t' || *end == '\r') end++;
	if (errno || *end || number > INT_MAX) return false;
	*value = (unsigned int)number;
	return true;
}
static bool unambiguous_interface(const struct iwinfo_ops *ops, const char *interface, char *buffer)
{
	char path[256];
	struct stat physical;
	/* nl80211's getters try a PHY name and a UCI wifi-device name before a
	 * netdev name. Even an alias resolving to this same PHY may select another
	 * interface, so accept only names which have neither interpretation. */
	if (!budget()) return false;
	if (!strncmp(interface, "mon.", 4)) {
		fatal = "interface_unavailable";
		return false;
	}
	snprintf(path, sizeof(path), MESH_RADIO_SYSFS "/ieee80211/%s", interface);
	int status = stat(path, &physical), error = errno;
	if (!budget()) return false;
	if (!status || (error != ENOENT && error != ENOTDIR)) {
		fatal = "interface_unavailable";
		return false;
	}
	memset(buffer, 0, IWINFO_BUFSIZE);
	if (!budget()) return false;
	status = ops->lookup_phy(interface, buffer);
	if (!budget()) return false;
	if (!status) {
		fatal = "interface_unavailable";
		return false;
	}
	return true;
}
static bool binding(const struct iwinfo_ops *ops, const char *radio, const char *interface,
		    char *buffer, struct binding *result)
{
	char path[256];
	struct stat physical, netdev, checked;
	memset(result, 0, sizeof(*result));
	memset(buffer, 0, IWINFO_BUFSIZE);
	if (!budget()) return false;
	int status = ops->lookup_phy(radio, buffer);
	if (!budget()) return false;
	if (status || !memchr(buffer, 0, sizeof(result->phy)) || !token(buffer, sizeof(result->phy)-1, true)) return false;
	strcpy(result->phy, buffer);
	/* nl80211_msg treats mon.NAME specially and an existing netdev takes
	 * precedence over a PHY argument for capability requests as well. */
	if (!strncmp(result->phy, "mon.", 4)) {
		fatal = "phy_unavailable";
		return false;
	}
	if (!budget()) return false;
	/* SIOCGIFINDEX on a missing name can invoke kernel dev_load(). A PHY is
	 * normally not a netdev, so test this interpretation through sysfs only. */
	snprintf(path, sizeof(path), MESH_RADIO_SYSFS "/net/%s", result->phy);
	status = lstat(path, &physical);
	int error = errno;
	if (!budget()) return false;
	if (!status || (error != ENOENT && error != ENOTDIR)) {
		fatal = "phy_unavailable";
		return false;
	}
	snprintf(path, sizeof(path), MESH_RADIO_SYSFS "/ieee80211/%s", result->phy);
	if (stat(path, &physical)) return false;
	result->device = physical.st_dev;
	result->inode = physical.st_ino;
	snprintf(path, sizeof(path), MESH_RADIO_SYSFS "/ieee80211/%s/index", result->phy);
	if (!read_number(path, &result->phy_index)) return false;
	if (interface) {
		unsigned int owner, index;
		/* Read the kernel's sysfs ifindex instead of SIOCGIFINDEX, including
		 * when the interface disappears during observation. Directory identity
		 * and the index are checked at both ends to reject recreation races. */
		snprintf(path, sizeof(path), MESH_RADIO_SYSFS "/net/%s", interface);
		if (stat(path, &netdev) || !S_ISDIR(netdev.st_mode)) return false;
		snprintf(path, sizeof(path), MESH_RADIO_SYSFS "/net/%s/ifindex", interface);
		if (!read_number(path, &result->ifindex) || !result->ifindex || !budget()) return false;
		if (!unambiguous_interface(ops, interface, buffer)) return false;
		snprintf(path, sizeof(path), MESH_RADIO_SYSFS "/net/%s/phy80211/index", interface);
		if (!read_number(path, &owner) || owner != result->phy_index) return false;
		snprintf(path, sizeof(path), MESH_RADIO_SYSFS "/net/%s/flags", interface);
		if (!read_number(path, &result->flags)) return false;
		snprintf(path, sizeof(path), MESH_RADIO_SYSFS "/net/%s/ifindex", interface);
		if (!read_number(path, &index) || index != result->ifindex) return false;
		snprintf(path, sizeof(path), MESH_RADIO_SYSFS "/net/%s", interface);
		if (stat(path, &checked) || !S_ISDIR(checked.st_mode) ||
		    checked.st_dev != netdev.st_dev || checked.st_ino != netdev.st_ino || !budget()) return false;
		result->net_device = netdev.st_dev;
		result->net_inode = netdev.st_ino;
	}
	return true;
}
static bool same_binding(const struct binding *a, const struct binding *b)
{
	return !strcmp(a->phy, b->phy) && a->phy_index == b->phy_index && a->device == b->device &&
		a->inode == b->inode && a->ifindex == b->ifindex && a->flags == b->flags &&
		a->net_device == b->net_device && a->net_inode == b->net_inode;
}
static void append(const char *format, ...)
{
	if (output_failed) return;
	va_list arguments;
	va_start(arguments, format);
	int size = vsnprintf(output + output_length, sizeof(output) - output_length, format, arguments);
	va_end(arguments);
	if (size < 0 || (size_t)size >= sizeof(output) - output_length) output_failed = true;
	else output_length += (size_t)size;
}
static void number(int value) { if (value == INT_MIN) append("null"); else append("%d", value); }
static const char *axis_status(struct axis axis)
{
	return !axis.count ? "unavailable" : axis.failed || axis.invalid || axis.truncated ? "partial" : "complete";
}
static unsigned int band_value(unsigned int band)
{
	switch (band) {
	case IWINFO_BAND_24: return 2;
	case IWINFO_BAND_5: return 5;
	case IWINFO_BAND_6: return 6;
	case IWINFO_BAND_60: return 60;
	default: return 0;
	}
}
static bool valid_frequency(unsigned int band, unsigned int frequency)
{
	return (band == 2 && frequency >= 2400 && frequency <= 2500) ||
		(band == 5 && frequency >= 4900 && frequency < 5925) ||
		(band == 6 && frequency >= 5925 && frequency <= 7125) ||
		(band == 60 && frequency >= 57000 && frequency <= 71000);
}
static bool frequency_known(int frequency)
{
	return frequency >= 0 && (valid_frequency(2, frequency) || valid_frequency(5, frequency) ||
		valid_frequency(6, frequency) || valid_frequency(60, frequency));
}
static int query_int(int (*method)(const char *, int *), const char *name, int *value)
{
	*value = INT_MIN;
	if (!budget()) return -1;
	int status = method ? method(name, value) : -1;
	if (!budget()) return -1;
	return status;
}

int main(int argc, char **argv)
{
	struct timespec now = {0};
	if (clock_gettime(CLOCK_MONOTONIC, &now)) fatal = "read_failed";
	started = (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
	const char *interface = argc == 3 ? argv[2] : NULL;
	if (argc < 2 || argc > 3 || !token(argv[1], 63, false) || (interface && !token(interface, IFNAMSIZ-1, true)))
		fatal = "invalid_request";
	const struct iwinfo_ops *ops = NULL;
	char *buffer = NULL;
	struct binding initial, final;
	struct channel channels[CHANNEL_LIMIT];
	unsigned int powers[POWER_LIMIT];
	struct axis channel_axis = {0}, power_axis = {0};
	char country[3] = {0};
	int channel = INT_MIN, frequency = INT_MIN, txpower = INT_MIN, offset = INT_MIN;
	bool partial = false, running = false;
	if (fatal) goto finish;
	if (!budget()) goto finish;
	ops = iwinfo_backend_by_name("nl80211");
	if (!budget()) goto finish;
	if (!ops || !ops->lookup_phy) { fatal = "backend_unavailable"; goto finish; }
	buffer = calloc(1, IWINFO_BUFSIZE);
	if (!buffer) { fatal = "read_failed"; goto finish; }
	if (!binding(ops, argv[1], interface, buffer, &initial)) {
		if (!fatal) fatal = interface ? "interface_unavailable" : "phy_unavailable";
		goto finish;
	}
	running = interface && (initial.flags & IFF_UP);
	issue("dfs_not_exposed");
	if (!running) issue("no_running_interface");
	if (running) {
		if (query_int(ops->channel, interface, &channel)) { issue("reported_channel_unavailable"); partial = true; channel = INT_MIN; }
		else if (channel < 1 || channel > 233) { issue("reported_channel_invalid"); partial = true; channel = INT_MIN; }
		if (query_int(ops->frequency, interface, &frequency)) { issue("reported_frequency_unavailable"); partial = true; frequency = INT_MIN; }
		else if (!frequency_known(frequency)) { issue("reported_frequency_invalid"); partial = true; frequency = INT_MIN; }
		if (query_int(ops->txpower, interface, &txpower)) { issue("reported_txpower_unavailable"); partial = true; txpower = INT_MIN; }
		else if (txpower < 0 || txpower > 63) { issue("reported_txpower_invalid"); partial = true; txpower = INT_MIN; }
		else if (!txpower) { issue("reported_txpower_zero_unverified"); partial = true; }
	}
	if (fatal) goto finish;
	const char *reference = running ? interface : initial.phy;
	if (query_int(ops->txpower_offset, reference, &offset)) { issue("offset_unavailable"); partial = true; offset = INT_MIN; }
	else if (offset < -32 || offset > 32) { issue("offset_invalid"); partial = true; offset = INT_MIN; }
	if (fatal) goto finish;
	memset(buffer, 0, IWINFO_BUFSIZE);
	if (!budget()) goto finish;
	int status = ops->country ? ops->country(initial.phy, buffer) : -1;
	if (!budget()) goto finish;
	if (status) { issue("country_unavailable"); partial = true; }
	else if (!((buffer[0] >= 'A' && buffer[0] <= 'Z' && buffer[1] >= 'A' && buffer[1] <= 'Z') ||
		   (buffer[0] == '0' && buffer[1] == '0')) || buffer[2]) { issue("country_invalid"); partial = true; }
	else memcpy(country, buffer, 2);
	memset(buffer, 0, IWINFO_BUFSIZE);
	int length = IWINFO_BUFSIZE;
	if (!budget()) goto finish;
	status = ops->freqlist ? ops->freqlist(initial.phy, buffer, &length) : -1;
	if (!budget()) goto finish;
	if (status) { channel_axis.failed = true; issue("channels_unavailable"); }
	else if (length < 0 || length > IWINFO_BUFSIZE || length % sizeof(struct iwinfo_freqlist_entry)) {
		channel_axis.invalid = true; issue("channels_invalid");
	} else {
		unsigned int count = (unsigned int)length / sizeof(struct iwinfo_freqlist_entry);
		if (!count) issue("channels_empty");
		if (count > CHANNEL_LIMIT) { channel_axis.truncated = true; issue("channels_truncated"); }
		for (unsigned int i = 0; i < count; i++) {
			struct iwinfo_freqlist_entry item;
			memcpy(&item, buffer + i * sizeof(item), sizeof(item));
			unsigned int band = band_value(item.band);
			bool duplicate = false;
			for (unsigned int j = 0; j < channel_axis.count; j++)
				if (channels[j].band == band && channels[j].frequency == item.mhz) duplicate = true;
			if (!band || !item.channel || item.channel > 233 || !valid_frequency(band, item.mhz) ||
			    item.restricted > 1 || item.flags & ~((1U << 9) - 1) || duplicate) {
				channel_axis.invalid = true; issue("channels_invalid"); continue;
			}
			if (channel_axis.count == CHANNEL_LIMIT) { channel_axis.truncated = true; issue("channels_truncated"); continue; }
			channels[channel_axis.count++] = (struct channel){band, item.channel, item.mhz, item.flags, item.restricted != 0};
		}
	}
	memset(buffer, 0, IWINFO_BUFSIZE);
	length = IWINFO_BUFSIZE;
	if (!budget()) goto finish;
	status = ops->txpwrlist ? ops->txpwrlist(reference, buffer, &length) : -1;
	if (!budget()) goto finish;
	if (status) { power_axis.failed = true; issue("power_unavailable"); }
	else if (length < 0 || length > IWINFO_BUFSIZE || length % sizeof(struct iwinfo_txpwrlist_entry)) {
		power_axis.invalid = true; issue("power_invalid");
	} else {
		unsigned int count = (unsigned int)length / sizeof(struct iwinfo_txpwrlist_entry);
		if (!count) issue("power_empty");
		if (count > POWER_LIMIT) { power_axis.truncated = true; issue("power_truncated"); }
		for (unsigned int i = 0; i < count; i++) {
			struct iwinfo_txpwrlist_entry item;
			memcpy(&item, buffer + i * sizeof(item), sizeof(item));
			bool duplicate = false;
			for (unsigned int j = 0; j < power_axis.count; j++) if (powers[j] == item.dbm) duplicate = true;
			if (item.dbm > 63 || duplicate) { power_axis.invalid = true; issue("power_invalid"); continue; }
			if (power_axis.count == POWER_LIMIT) { power_axis.truncated = true; issue("power_truncated"); continue; }
			powers[power_axis.count++] = item.dbm;
		}
	}
	if (running) {
		int current;
		if (query_int(ops->channel, interface, &current) || current < 1 || current > 233) current = INT_MIN;
		if (!fatal && current != channel) fatal = "target_changed";
		if (fatal) goto finish;
		if (query_int(ops->frequency, interface, &current) || !frequency_known(current)) current = INT_MIN;
		if (!fatal && current != frequency) fatal = "target_changed";
	}
	if (fatal) goto finish;
	if (!binding(ops, argv[1], interface, buffer, &final) || !same_binding(&initial, &final)) {
		if (!fatal) fatal = "target_changed";
		goto finish;
	}
	if (!budget()) goto finish;
	if (channel != INT_MIN && frequency != INT_MIN && channel_axis.count) {
		bool matched = false;
		for (unsigned int i = 0; i < channel_axis.count; i++)
			if (channels[i].channel == (unsigned int)channel && channels[i].frequency == (unsigned int)frequency) matched = true;
		if (!matched) { issue("reported_channel_mismatch"); partial = true; }
	}
	partial = partial || strcmp(axis_status(channel_axis), "complete") || strcmp(axis_status(power_axis), "complete");
	const char *state = !channel_axis.count && !power_axis.count ? "unavailable" : partial ? "partial" : "complete";
	append("{\"schema\":1,\"status\":\"%s\",\"radio\":\"%s\",\"phy\":\"%s\",\"representative_interface\":", state, argv[1], initial.phy);
	if (interface) append("\"%s\"", interface); else append("null");
	append(",\"reported\":{\"channel\":"); number(channel);
	append(",\"frequency_mhz\":"); number(frequency);
	append(",\"country\":"); if (country[0]) append("\"%s\"", country); else append("null");
	append(",\"txpower_dbm\":"); number(txpower);
	append(",\"txpower_offset_db\":"); number(offset);
	append(",\"actual_txpower_dbm\":null,\"txpower_source\":\"%s\",\"source\":\"libiwinfo\"},", txpower == INT_MIN ? "unavailable" : txpower ? "backend_reported" : "zero_unverified");
	append("\"channels\":{\"status\":\"%s\",\"complete\":%s,\"truncated\":%s,\"items\":[", axis_status(channel_axis), !strcmp(axis_status(channel_axis), "complete") ? "true" : "false", channel_axis.truncated ? "true" : "false");
	for (unsigned int i = 0; i < channel_axis.count; i++) {
		struct channel *item = &channels[i];
		append("%s{\"band\":%u,\"channel\":%u,\"frequency_mhz\":%u,\"restricted\":%s,\"flags\":[", i ? "," : "", item->band, item->channel, item->frequency, item->restricted ? "true" : "false");
		bool first = true;
		for (unsigned int j = 0; j < 9; j++) if (item->flags & (1U << j)) {
			append("%s\"%s\"", first ? "" : ",", flag_names[j]); first = false;
		}
		append("],\"dfs_required\":null}");
	}
	/* txpwrlist internally samples the channel again and may fall back to all
	 * channels on failure, or match equal channel numbers across bands. Our
	 * surrounding reads do not prove the list's frequency scope. Keep its
	 * candidates unscoped; the separate reported block is only a reference. */
	append("]},\"power\":{\"status\":\"%s\",\"complete\":%s,\"truncated\":%s,\"scope\":\"operating_channel_unknown\",\"channel\":null", axis_status(power_axis), !strcmp(axis_status(power_axis), "complete") ? "true" : "false", power_axis.truncated ? "true" : "false");
	append(",\"raw_dbm\":[");
	for (unsigned int i = 0; i < power_axis.count; i++) append("%s%u", i ? "," : "", powers[i]);
	append("],\"offset_db\":"); number(offset);
	append("},\"dfs_complete\":false,\"dfs_source\":\"not_exposed_by_backend\",\"issues\":[");
	for (unsigned int i = 0; i < issue_count; i++) append("%s\"%s\"", i ? "," : "", issues[i]);
	append("]}\n");
	if (output_failed) fatal = "result_too_large";
finish:
	free(buffer);
	if (ops && budget()) { iwinfo_finish(); budget(); }
	if (!fatal) budget();
	if (fatal) { printf("{\"schema\":1,\"status\":\"unavailable\",\"reason\":\"%s\"}\n", fatal); return 1; }
	fputs(output, stdout);
	return 0;
}
