// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { validate, equal, public_op } from './model.uc';
import { compile_extended, validate_controller_management, CONTROLLER_ADDRESS_MESSAGE } from './extended.uc';
import { port_tokens as tokens, device_path } from './topology.uc';
import { valid_anchor } from './authority.uc';

function enabled(value) {
	if (value == null || value === false || value === 0) return false;
	return type(value) != 'string' || index(['', '0', 'false', 'no', 'off'], lc(trim(value))) < 0;
}

export function value(snapshot, op) {
	let section = snapshot[op.config]?.[op.section];
	return op.option == null ? section : section?.values?.[op.option];
}

function compile_legacy(intent, snapshot, capabilities, owned) {
	let errors = validate(intent),
		ops = [],
		conflicts = [],
		warnings = [];
	function fail(code, message) {
		push(errors, { code, message });
	}
	let identity=capabilities.controller_identity;
	if (identity?.role == 'root' || valid_anchor(identity?.anchor) && identity.anchor.id==identity.id) {
		let address=identity.anchor && identity.anchor.id==identity.id ? identity.anchor.address : identity.address;
		try { validate_controller_management({ management: intent?.management }, address, null, identity); }
		catch (e) { fail('controller_address_unsupported', CONTROLLER_ADDRESS_MESSAGE); }
	}
	if (length(errors)) return { errors, ops, conflicts, warnings };
	function field(config, section, option, after, reason) {
		let old = snapshot[config]?.[section];
		if (!old) {
			fail('missing_section', config + '.' + section + ' is missing');
			return;
		}
		let before = old.values[option];
		push(ops, {
			config,
			section,
			option,
			type: old.type,
			before: before ?? null,
			after,
			reason,
			changed: !equal(before, after)
		});
	}
	let lan = snapshot.network?.lan;
	if (lan?.type != 'interface' || index(['static', 'dhcp'], lan?.values?.proto) < 0)
		fail('unsupported_lan', 'A standard static/DHCP network.lan is required');
	let bridge = filter(
		keys(snapshot.network || {}),
		(k) =>
			snapshot.network[k].type == 'device' && snapshot.network[k].values.name == lan?.values?.device
	);
	let vlans = filter(
		keys(snapshot.network || {}),
		(k) =>
			snapshot.network[k].type == 'bridge-vlan' &&
			index(tokens(snapshot.network[k].values.device) || [], lan?.values?.device) >= 0
	);
	if (
		length(bridge) != 1 ||
		snapshot.network[bridge[0]].values.type != 'bridge' ||
		enabled(snapshot.network[bridge[0]].values.vlan_filtering) ||
		length(vlans)
	)
		fail('unsupported_bridge', 'A non-VLAN-filtering LAN bridge is required');
	if (!length(tokens(snapshot.network?.[bridge[0]]?.values?.ports) || []))
		fail('missing_ports', 'LAN bridge needs existing wired ports');
	if (lan?.values?.ip6addr || lan?.values?.ip6gw)
		fail('ipv6_conflict', 'Static IPv6 LAN overrides require manual review');
	if (capabilities.pending_changes)
		fail('pending_uci', 'Apply or discard pending UCI changes before takeover');
	if (!capabilities.dnsmasq || !capabilities.firewall)
		fail('missing_dependency', 'dnsmasq and firewall4 services are required');
	let dhcp = filter(
		keys(snapshot.dhcp || {}),
		(k) => snapshot.dhcp[k].type == 'dhcp' && snapshot.dhcp[k].values.interface == 'lan'
	);
	if (length(dhcp) != 1) fail('dhcp_conflict', 'Exactly one DHCP section for LAN is required');
	let zones = filter(
		keys(snapshot.firewall || {}),
		(k) => snapshot.firewall[k].type == 'zone' && snapshot.firewall[k].values.name == 'lan'
	);
	if (
		length(zones) != 1 ||
		index(tokens(snapshot.firewall?.[zones[0]]?.values?.network) || [], 'lan') < 0
	)
		fail('firewall_conflict', 'Standard LAN firewall zone is required');
	let forwards = filter(
		keys(snapshot.firewall || {}),
		(k) => snapshot.firewall[k].type == 'forwarding' && snapshot.firewall[k].values.src == 'lan'
	);
	let wanzone = filter(
		keys(snapshot.firewall || {}),
		(k) => snapshot.firewall[k].type == 'zone' && snapshot.firewall[k].values.name == 'wan'
	);
	if (intent.gateway == 'router') {
		let wan = snapshot.network?.wan;
		let managed_nat = filter(
			owned || [],
			(o) =>
				o.config == 'firewall' && o.section == wanzone[0] && o.option == 'masq' && o.before == '1'
		);
		if (
			!wan ||
			index(['none', '', null], wan.values.proto) >= 0 ||
			length(wanzone) != 1 ||
			(snapshot.firewall[wanzone[0]].values.masq != '1' && !length(managed_nat)) ||
			!length(filter(forwards, (k) => snapshot.firewall[k].values.dest == 'wan'))
		)
			fail(
				'missing_gateway',
				'Configure WAN, WAN masquerading and LAN-to-WAN forwarding separately first'
			);
		let lan_path = device_path(snapshot, lan?.values?.device, []),
			wan_path = device_path(snapshot, wan?.values?.device, []);
		if (lan_path == null || wan_path == null)
			fail(
				'unsupported_topology',
				'WAN/LAN device separation cannot be resolved from local configuration'
			);
		else if (length(filter(wan_path, (device) => index(lan_path, device) >= 0)))
			fail(
				'gateway_overlap',
				'WAN and LAN share a bridge or lower device; separate them before enabling routing'
			);
	}
	if (length(errors)) return { errors, ops: [], conflicts, warnings };
	field('network', 'lan', 'proto', intent.management.protocol, 'management protocol');
	field(
		'network',
		'lan',
		'ipaddr',
		intent.management.protocol == 'static' ? intent.management.address : null,
		'management address'
	);
	field(
		'network',
		'lan',
		'netmask',
		intent.management.protocol == 'static' ? intent.management.netmask : null,
		'management netmask'
	);
	if (intent.management.protocol == 'dhcp') {
		field('network', 'lan', 'gateway', null, 'use upstream DHCP gateway');
		field('network', 'lan', 'dns', null, 'use upstream DHCP DNS');
	}
	field(
		'network',
		'lan',
		'ip6assign',
		intent.gateway == 'router' ? lan.values.ip6assign || '60' : null,
		'IPv6 gateway role'
	);
	field('dhcp', dhcp[0], 'ignore', intent.gateway == 'router' ? '0' : '1', 'DHCP gateway role');
	field('dhcp', dhcp[0], 'ra', intent.gateway == 'router' ? 'server' : 'disabled', 'IPv6 RA role');
	field(
		'dhcp',
		dhcp[0],
		'dhcpv6',
		intent.gateway == 'router' ? 'server' : 'disabled',
		'DHCPv6 role'
	);
	field('dhcp', dhcp[0], 'ndp', 'disabled', 'disable ND proxy');
	for (let k in forwards) {
		let previous = filter(
			owned || [],
			(o) => o.config == 'firewall' && o.section == k && o.option == 'enabled'
		)[0];
		if (intent.gateway == 'router' && snapshot.firewall[k].values.dest != 'wan' && !previous)
			continue;
		field(
			'firewall',
			k,
			'enabled',
			intent.gateway != 'router'
				? '0'
				: snapshot.firewall[k].values.dest == 'wan'
					? '1'
					: previous.before,
			'gateway forwarding role'
		);
	}
	if (length(wanzone) == 1)
		for (let option in ['masq', 'masq6']) {
			let previous = filter(
				owned || [],
				(o) => o.config == 'firewall' && o.section == wanzone[0] && o.option == option
			)[0];
			if (intent.gateway != 'router' || previous)
				field(
					'firewall',
					wanzone[0],
					option,
					intent.gateway != 'router' ? '0' : previous.before,
					'NAT gateway role'
				);
		}
	if (
		length(
			filter(
				keys(snapshot.firewall),
				(k) => snapshot.firewall[k].type == 'include' && snapshot.firewall[k].values.enabled != '0'
			)
		)
	)
		push(
			warnings,
			'External firewall includes are outside managed ownership; review their NAT/forwarding behavior'
		);
	for (let radio in intent.wifi.radios) {
		if (snapshot.wireless?.[radio]?.type != 'wifi-device') {
			fail('unknown_radio', 'Radio is not present: ' + radio);
			continue;
		}
		if (!intent.wifi.enabled) continue;
		if (!capabilities.hostapd)
			fail('missing_dependency', 'A working hostapd/wpad installation is required');
		if (intent.wifi.encryption == 'sae-mixed' && !capabilities.sae) {
			if (index(capabilities.wireless_probe_errors || [], 'sae') >= 0)
				fail('wireless_probe_unavailable', 'Wireless capability probe failed; retry the preflight');
			else fail('missing_sae', 'SAE capability has not been verified');
		}
		field('wireless', radio, 'disabled', '0', 'enable selected radio');
		let name = 'mm_ap_' + radio,
			current = snapshot.wireless[name];
		let is_owned = length(
			filter(owned || [], (o) => o.config == 'wireless' && o.section == name && o.option == null)
		);
		if (current && !is_owned) {
			fail('reserved_section', 'Existing unowned section: ' + name);
			continue;
		}
		for (let k in keys(snapshot.wireless || {})) {
			let s = snapshot.wireless[k];
			if (
				s.type != 'wifi-iface' ||
				s.values.device != radio ||
				s.values.disabled == '1' ||
				k == name
			)
				continue;
			if (
				s.values.mode != 'ap' ||
				(!equal(s.values.network, 'lan') && !equal(s.values.network, ['lan']))
			) {
				fail('wireless_conflict', 'Existing mesh, station or non-LAN AP on ' + radio + ': ' + k);
				continue;
			}
			push(conflicts, {
				config: 'wireless',
				section: k,
				message: 'Existing AP will be disabled; its settings will not be copied'
			});
			field('wireless', k, 'disabled', '1', 'explicit AP takeover');
		}
		let after = {
			type: 'wifi-iface',
			values: {
				device: radio,
				mode: 'ap',
				network: 'lan',
				ssid: intent.wifi.ssid,
				encryption: intent.wifi.encryption,
				key: intent.wifi.key,
				disabled: '0'
			}
		};
		push(ops, {
			config: 'wireless',
			section: name,
			option: null,
			type: 'wifi-iface',
			before: current ?? null,
			after,
			reason: 'managed AP',
			changed: !equal(current, after)
		});
	}
	for (let item in owned || []) {
		if (item.config != 'wireless' || item.option != null || !match(item.section, /^mm_ap_/))
			continue;
		let current = snapshot.wireless?.[item.section];
		if (
			!current ||
			(intent.wifi.enabled &&
				index(
					map(intent.wifi.radios, (r) => 'mm_ap_' + r),
					item.section
				) >= 0)
		)
			continue;
		if (!equal(current, item.after))
			fail('ownership_conflict', 'Managed AP has external modifications: ' + item.section);
		else
			push(ops, { ...item, before: current, after: null, reason: 'remove deselected managed AP' });
	}
	push(warnings, 'No remote pairing or wireless backhaul is implemented in this version');
	push(
		warnings,
		'Address conflict detection and hidden wired loop detection have not been performed'
	);
	push(
		warnings,
		'Management address changes may disconnect this browser; reconnect and confirm before timeout'
	);
	if (intent.gateway != 'router' && intent.management.protocol == 'static')
		push(
			warnings,
			'Static bridge management keeps any existing local gateway/DNS overrides; verify them separately'
		);
	return {
		errors,
		ops: length(errors) ? [] : ops,
		conflicts,
		warnings,
		dangerous: length(filter(ops, (o) => o.config == 'network')) > 0
	};
}

export function compile(intent, snapshot, capabilities, owned, resume_steering) {
	return intent?.schema == 2
		? compile_extended(intent, snapshot, capabilities, owned, compile_legacy, resume_steering)
		: compile_legacy(intent, snapshot, capabilities, owned);
}
export function preview(plan) {
	return { ...plan, ops: map(plan.ops, public_op) };
}
