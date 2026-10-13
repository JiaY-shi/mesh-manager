// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { equal as native_equal } from 'mesh_data';

export function public_enrollment(e) {
	return e ? { enabled: e.enabled === true, status: e.status, error: e.error || null,
		cycle: e.cycle || 0, candidates: e.candidates || [], access_points: e.access_points || [] } : null;
}

export function clone(value) {
	return json(sprintf('%J', value));
}

export function canonical(value) {
	if (type(value) == 'object') {
		let out = {};
		for (let key in sort(keys(value))) out[key] = canonical(value[key]);
		return out;
	}
	if (type(value) == 'array') return map(value, canonical);
	return value;
}

export function equal(a, b) {
	return native_equal(a, b);
}

export function public_intent(intent) {
	if (!intent) return null;
	let result = clone(intent);
	delete result.wifi.key;
	if (type(result.backhaul) == 'object') delete result.backhaul.key;
	for (let network in result.networks || []) delete network.key;
	return result;
}

export function public_op(op) {
	let result = clone(op);
	if (op.secret || index(['key', 'password', 'auth_secret'], op.option) >= 0) {
		result.before = op.before == null ? null : '[redacted]';
		result.after = op.after == null ? null : '[redacted]';
	}
	if (op.option == null) {
		for (let side in ['before', 'after'])
			for (let key in ['key', 'password', 'auth_secret'])
				if (result[side]?.values?.[key] != null) result[side].values[key] = '[redacted]';
	}
	return result;
}

export function ipv4(value) {
	if (type(value) != 'string') return false;
	let parsed = match(value, /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/);
	if (!parsed || parsed[0] != value) return false;
	let parts = split(value, '.');
	return !length(
		filter(parts, (p) => length(p) > 3 || int(p) > 255 || (length(p) > 1 && substr(p, 0, 1) == '0'))
	);
}

export function static_ipv4_matches(options, addresses) {
	let configured = type(options?.ipaddr) == 'array' ? options.ipaddr : [options?.ipaddr];
	if (!length(configured) || type(addresses) != 'array') return false;
	let default_prefix = 32;
	if (options.netmask != null) {
		if (!ipv4(options.netmask)) return false;
		let zero = false;
		default_prefix = 0;
		for (let octet in split(options.netmask, '.'))
			for (let bit = 7; bit >= 0; bit--) {
				if (int(octet) & (1 << bit)) {
					if (zero) return false;
					default_prefix++;
				} else zero = true;
			}
	}
	for (let item in configured) {
		if (type(item) != 'string') return false;
		let parts = split(item, '/'),
			prefix = default_prefix;
		if (length(parts) > 2 || !ipv4(parts[0])) return false;
		if (length(parts) == 2) {
			if (!match(parts[1], /^[0-9]{1,2}$/) || int(parts[1]) > 32) return false;
			prefix = int(parts[1]);
		}
		if (!length(filter(addresses, (a) => a.address == parts[0] && a.mask == prefix))) return false;
	}
	return true;
}

function unsafe_text(value, ascii) {
	for (let i = 0; i < length(value); i++) {
		let code = ord(value, i);
		if (code < 32 || code == 127 || (ascii && code > 126)) return true;
	}
	return false;
}

export function valid_text(value, minimum, maximum, ascii) {
	return (
		type(value) == 'string' &&
		length(value) >= minimum &&
		length(value) <= maximum &&
		!unsafe_text(value, ascii)
	);
}
export function validate(intent) {
	let errors = [];
	function error(path, text) {
		push(errors, { code: 'invalid_intent', path, message: text });
	}
	function object(value, path, allowed) {
		if (type(value) != 'object') {
			error(path, 'Expected an object');
			return false;
		}
		for (let key in keys(value))
			if (index(allowed, key) < 0) error(path + '.' + key, 'Unknown field');
		return true;
	}
	if (
		!object(intent, 'intent', [
			'schema',
			'name',
			'controller',
			'gateway',
			'management',
			'backhaul',
			'wifi'
		])
	)
		return errors;
	if (intent.schema != 1) error('schema', 'Only schema 1 is supported');
	if (
		type(intent.name) != 'string' ||
		!length(intent.name) ||
		length(intent.name) > 64 ||
		unsafe_text(intent.name)
	)
		error('name', 'Name must contain 1 to 64 bytes without control characters');
	if (type(intent.controller) != 'bool') error('controller', 'Controller must be boolean');
	if (
		index(['router', 'bridge'], intent.gateway) < 0 ||
		(!intent.controller && intent.gateway != 'bridge')
	)
		error('gateway', 'AP must use bridge mode');
	if (intent.backhaul != 'wired')
		error('backhaul', 'Only existing wired LAN backhaul is implemented');
	if (object(intent.management, 'management', ['interface', 'protocol', 'address', 'netmask'])) {
		for (let field in ['address', 'netmask'])
			if (
				intent.management[field] != null &&
				(type(intent.management[field]) != 'string' || length(intent.management[field]) > 15)
			)
				error('management.' + field, 'Expected a short IPv4 string');
		if (intent.management.interface != 'lan')
			error('management.interface', 'Only the existing standard LAN is supported');
		if (index(['dhcp', 'static'], intent.management.protocol) < 0)
			error('management.protocol', 'Select static or DHCP');
		if (intent.gateway == 'router' && intent.management.protocol != 'static')
			error('management.protocol', 'Gateway LAN requires a static address');
		if (intent.management.protocol == 'static') {
			if (!ipv4(intent.management.address)) error('management.address', 'Invalid IPv4 address');
			if (!ipv4(intent.management.netmask)) error('management.netmask', 'Invalid netmask');
			else {
				let mask = 0;
				for (let p in split(intent.management.netmask, '.')) mask = (mask << 8) | int(p);
				let inverse = 0xffffffff ^ mask;
				if (inverse < 3 || inverse > 0x7fffffff || (inverse & (inverse + 1)) != 0)
					error('management.netmask', 'Use a contiguous /1 to /30 mask');
				if (ipv4(intent.management.address)) {
					let host = 0,
						ones = 0;
					let a = split(intent.management.address, '.'),
						m = split(intent.management.netmask, '.');
					for (let i = 0; i < 4; i++) {
						host = (host << 8) | (int(a[i]) & (255 ^ int(m[i])));
						ones = (ones << 8) | (255 ^ int(m[i]));
					}
					if (host == 0 || host == ones || int(a[0]) == 0 || int(a[0]) == 127 || int(a[0]) >= 224)
						error('management.address', 'Not a usable unicast host address');
				}
			}
		}
	}
	if (object(intent.wifi, 'wifi', ['enabled', 'ssid', 'encryption', 'key', 'radios'])) {
		if (
			intent.wifi.ssid != null &&
			(type(intent.wifi.ssid) != 'string' || length(intent.wifi.ssid) > 32)
		)
			error('wifi.ssid', 'SSID must be a string of at most 32 bytes');
		if (
			intent.wifi.key != null &&
			(type(intent.wifi.key) != 'string' || length(intent.wifi.key) > 63)
		)
			error('wifi.key', 'Passphrase must be a string of at most 63 bytes');
		if (intent.wifi.encryption != null && index(['psk2', 'sae-mixed'], intent.wifi.encryption) < 0)
			error('wifi.encryption', 'Unsupported encryption');
		if (type(intent.wifi.enabled) != 'bool') error('wifi.enabled', 'Enabled must be boolean');
		if (
			type(intent.wifi.radios) != 'array' ||
			length(intent.wifi.radios) > 8 ||
			length(uniq(intent.wifi.radios || [])) != length(intent.wifi.radios || [])
		)
			error('wifi.radios', 'Choose at most eight distinct radios');
		else
			for (let radio in intent.wifi.radios)
				if (type(radio) != 'string' || !match(radio, /^[a-zA-Z][a-zA-Z0-9_]{0,31}$/))
					error('wifi.radios', 'Invalid radio section name');
		if (intent.wifi.enabled) {
			if (
				type(intent.wifi.ssid) != 'string' ||
				!length(intent.wifi.ssid) ||
				length(intent.wifi.ssid) > 32 ||
				unsafe_text(intent.wifi.ssid)
			)
				error('wifi.ssid', 'SSID must contain 1 to 32 bytes without control characters');
			if (index(['psk2', 'sae-mixed'], intent.wifi.encryption) < 0)
				error('wifi.encryption', 'Unsupported encryption');
			if (
				type(intent.wifi.key) != 'string' ||
				length(intent.wifi.key) < 8 ||
				length(intent.wifi.key) > 63 ||
				unsafe_text(intent.wifi.key, true)
			)
				error('wifi.key', 'Use an 8 to 63 character printable ASCII passphrase');
			if (!length(intent.wifi.radios || [])) error('wifi.radios', 'Select at least one radio');
		}
	}
	return errors;
}
