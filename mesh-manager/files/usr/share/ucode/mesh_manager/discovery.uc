// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import { connect } from 'ubus';
import { run } from 'mesh_process';
import { private_address } from './identity.uc';
import { valid_text } from './model.uc';

const SERVICE = '_mesh-manager._tcp';

function wifi_device_names(status) {
	let names = [];
	for (let name in keys(status || {})) {
		let radio = status[name];
		if (!radio?.up) continue;
		// iwinfo can scan an idle phy using its UCI radio name without
		// enabling a production AP or changing its configuration.
		if (type(radio.interfaces) == 'array' && !length(radio.interfaces) &&
			radio.config?.type == 'mac80211' && match(name, /^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/)) {
			push(names, name);
			continue;
		}
		for (let iface in radio.interfaces || []) {
			let name = iface.ifname;
			if (iface.config?.mode == 'ap' &&
				match(name || '', /^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/) &&
				index(names, name) < 0)
				push(names, name);
		}
	}
	return slice(names, 0, 2);
}

export function parse_access_points(scan, device) {
	let result = [];
	for (let ap in scan?.results || []) {
		if (!valid_text(ap.ssid, 1, 32) ||
			!match(ap.bssid || '', /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/) ||
			ap.mode != 'Master' ||
			!match(device || '', /^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/) ||
			type(ap.signal) != 'int' || ap.signal < -127 || ap.signal > 0 ||
			index(ap.encryption?.authentication || [], 'psk') < 0 &&
			index(ap.encryption?.authentication || [], 'sae') < 0)
			continue;
		push(result, {
			ssid: ap.ssid,
			bssid: lc(ap.bssid),
			device,
			channel: ap.channel,
			signal: ap.signal,
			verified: false
		});
	}
	return result;
}

function monotonic() {
	return +split(fs.readfile('/proc/uptime') || '0 ', ' ')[0];
}

function scan_device(device, milliseconds) {
	let request = sprintf('%J', { device }), result = run(
		['/bin/ubus', '-t', '' + min(6, int((milliseconds + 999) / 1000)),
			'call', 'iwinfo', 'scan', request], '', milliseconds
	);
	if (result?.code != 0) return null;
	try { return json(result.stdout); }
	catch (e) { return null; }
}

// Internal recovery callers verify their bound AP's complete original scope
// before this read-only scan. The public discovery method retains its role gate.
export function scan_wireless(bus,scanner,selected_device,max_seconds) {
	let budget = max_seconds == null ? 10 : max_seconds;
	if (type(budget) != 'int' || budget < 1 || budget > 20)
		die('invalid_window: Wireless scan must be limited to 1-20 seconds');
	let deadline = monotonic() + budget;
	let connection = bus || connect(null, 2);
	if (!connection) return { available: false, access_points: [], reason: 'ubus unavailable' };
	let result = { available: false, access_points: [], verified: false };
	try {
		let status = connection.call('network.wireless', 'status', {}),
			devices = wifi_device_names(status), seen = {};
		if (selected_device)
			devices = filter(devices, (device) => device == selected_device);
		for (let device in devices) {
			let remaining = int((deadline - monotonic()) * 1000);
			if (remaining < 1) break;
			let scan = (scanner || scan_device)(device, remaining);
			if (!scan) continue;
			result.available = true;
			for (let ap in parse_access_points(scan, device)) {
				let key = ap.bssid;
				if (!seen[key] || seen[key].signal < ap.signal) seen[key] = ap;
			}
		}
		result.access_points = sort(values(seen), (a, b) => b.signal - a.signal);
		if (!length(devices)) result.reason = 'no active AP radio available for scan';
		else if (!result.available) result.reason = 'wireless scan unavailable';
	} catch (e) {
		result.reason = 'wireless scan failed';
	}
	if (!bus) connection.disconnect();
	return result;
}
export function discover_wireless(identity, bus, scanner, selected_device, max_seconds) {
	if (identity != null && identity?.role != 'unbound')
		return { available: false, access_points: [], reason: 'node already enrolled' };
	return scan_wireless(bus,scanner,selected_device,max_seconds);
}


// DNS-SD is an untrusted hint. Enrollment still pins the CA and controller ID.
export function parse_candidates(browse, identity) {
	let services = browse?.[SERVICE] || {}, candidates = [];
	for (let instance in keys(services)) {
		let record = services[instance], txt = {};
		for (let entry in record?.txt || []) {
			let parts = split(entry, '=', 2);
			if (length(parts) == 2 && index(['id', 'network', 'ca', 'name', 'role'], parts[0]) >= 0)
				txt[parts[0]] = parts[1];
		}
		if (
			txt.role != 'root' ||
			!match(txt.id || '', /^[0-9a-f]{32}$/) ||
			!match(txt.network || '', /^[0-9a-f]{32}$/) ||
			!match(txt.ca || '', /^[0-9a-f]{64}$/) ||
			!valid_text(txt.name, 1, 64) ||
			record.port != 37902 ||
			!match(record.iface || '', /^[a-zA-Z0-9_.-]{1,32}$/)
		) continue;
		let addresses = type(record.ipv4) == 'array' ? record.ipv4 : [record.ipv4];
		let address = filter(addresses, private_address)[0];
		if (!address || txt.id == identity?.id) continue;
		push(candidates, {
			name: txt.name,
			controller_id: txt.id,
			network_id: txt.network,
			fingerprint: txt.ca,
			address,
			interface: record.iface,
			verified: false,
			binding_conflict: identity?.role == 'ap' &&
				(identity.binding?.controller_id != txt.id || identity.binding?.network_id != txt.network)
		});
	}
	return sort(candidates, (a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
}

export function wired_gateways(status) {
	let gateways = [];
	for (let iface in status?.interface || []) {
		let device = iface.l3_device, addresses = iface['ipv4-address'] || [];
		if (!iface.up || iface.proto != 'dhcp' || !match(device || '', /^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/)) continue;
		for (let route in iface.route || []) {
			let address = route.nexthop;
			if (route.target != '0.0.0.0' || route.mask != 0 || !private_address(address)) continue;
			let octets = map(split(address, '.'), item => int(item));
			let connected = length(filter(addresses, local => {
				if (!private_address(local.address) || type(local.mask) != 'int' || local.mask < 1 || local.mask > 30 || local.address == address) return false;
				let parts = map(split(local.address, '.'), item => int(item)), remaining = local.mask;
				for (let n=0;n<4;n++) {
					let bits = min(8, remaining), mask = bits ? (255 << (8-bits)) & 255 : 0;
					if ((parts[n] & mask) != (octets[n] & mask)) return false;
					remaining -= bits;
				}
				return true;
			}));
			if (connected && !length(filter(gateways, g => g.address == address && g.interface == device))) push(gateways, { address, interface:device });
		}
	}
	return slice(gateways, 0, 4);
}

// This is only a local observation, never permission to join. Reuse the
// netifd dump already needed for gateway discovery; do not probe from status.
export function wired_address_error(status) {
	let dhcp = filter(type(status?.interface) == 'array' ? status.interface : [],
		iface => iface.proto == 'dhcp' &&
			match(iface.l3_device || iface.device || '', /^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/));
	for (let iface in dhcp)
		for (let local in iface['ipv4-address'] || [])
			if (match(local.address || '', /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/) &&
				local.address != '0.0.0.0' &&
				!length(filter(split(local.address, '.'), part => int(part) > 255))) return null;
	return length(dhcp) ? 'wired_no_address' : null;
}

function inspect_gateway(gateway, milliseconds) {
	let result = run(['/usr/libexec/mesh-manager-channel','inspect',gateway.address,'37902',gateway.interface], '', milliseconds);
	if (result?.code != 0) return null;
	try { let reply = json(result.stdout); return reply?.ok === true ? reply.data : null; }
	catch (e) { return null; }
}

export function discover(identity, bus, inspector) {
	let connection = bus || connect(null, 1);
	if (!connection) return { available: false, candidates: [], reason: 'umdns unavailable' };
	let result;
	try {
		connection.error();
		connection.call('umdns', 'query', { question: SERVICE + '.local' });
		if (connection.error() != null)
			result = { available: false, candidates: [], reason: 'umdns query unavailable' };
		else {
			let browse = connection.call('umdns', 'browse', {
				service: SERVICE, array: true, address: true
			});
			result = connection.error() != null
				? { available: false, candidates: [], reason: 'umdns browse unavailable' }
				: { available: true, candidates: parse_candidates(browse, identity), verified: false };
		}
	} catch (e) {
		result = { available: false, candidates: [], reason: 'umdns request failed' };
	}
	// Default umdns listens on LAN only. An unbound AP can also inspect its
	// connected DHCP gateway, without changing umdns or sending credentials.
	if (identity?.role == 'unbound' && !length(result.candidates)) {
		try {
			let status = connection.call('network.interface', 'dump', {}),
				gateways = wired_gateways(status), deadline = monotonic() + 3;
			if (connection.error() == null) result.error = wired_address_error(status);
			for (let gateway in gateways) {
				let remaining = min(1500, int((deadline-monotonic())*1000));
				if (remaining < 1) break;
				let info = (inspector || inspect_gateway)(gateway, remaining);
				if (!info || info.address != gateway.address || info.enroll_port != 37902) continue;
				let candidates = parse_candidates({ [SERVICE]: { gateway: {
					iface:gateway.interface, port:info.enroll_port, ipv4:[info.address],
					txt:['role=root','id='+info.controller_id,'network='+info.network_id,'ca='+info.fingerprint,'name='+info.name]
				} } }, identity);
				for (let candidate in candidates) if (!length(filter(result.candidates, c => c.controller_id == candidate.controller_id && c.address == candidate.address))) push(result.candidates,candidate);
			}
			if (length(result.candidates)) { result.available = true; delete result.reason; }
		} catch (e) { /* Missing DHCP telemetry must not discard DNS-SD results. */ }
	}
	if (!bus) connection.disconnect();
	return result;
}
