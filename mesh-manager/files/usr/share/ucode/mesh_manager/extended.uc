// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal, validate, valid_text } from './model.uc';
import { control_addresses } from './backhaul.uc';
import { require_lease } from './control_lease.uc';
import { port_tokens, uplink_conflicts } from './topology.uc';
import { private_address } from './identity.uc';
import { steering_plan, steering_policy_errors } from './roaming.uc';
import { backhaul_mode } from './radio_modes.uc';

export const CONTROLLER_ADDRESS_MESSAGE = 'Coordinated controller address migration is not implemented; preserve the existing static LAN address';
export function validate_controller_management(local, address, lan) {
	let management = local?.management;
	if (!private_address(address) || management?.interface != 'lan' ||
		management.protocol != 'static' || management.address != address)
		die('controller_address_unsupported: ' + CONTROLLER_ADDRESS_MESSAGE);
	if (lan != null) {
		let configured = type(lan.ipaddr) == 'array' ? lan.ipaddr : [lan.ipaddr];
		if (lan.proto != 'static' || !length(filter(configured,
			item => type(item) == 'string' && split(item, '/')[0] == address)))
			die('controller_address_unsupported: ' + CONTROLLER_ADDRESS_MESSAGE);
	}
	return true;
}
function safe_name(n) {
	return type(n) == 'string' && match(n, /^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/);
}
export function mesh_mac(id) {
	if (!match(id || '', /^[0-9a-f]{32}$/)) die('invalid_identity: Cannot derive mesh address');
	return (
		'02:' +
		join(
			':',
			map([0, 2, 4, 6, 8], (i) => substr(id, i, 2))
		)
	);
}
export function validate_overrides(local) {
	if (type(local) != 'object')
		die('invalid_override: Local radio and management overrides are required');
	for (let k in keys(local))
		if (
			index(
				[
					'name',
					'radios',
					'mesh_radio',
					'uplink',
					'management',
					'gateway',
					'disable_legacy_mesh',
					'mac',
					'peers'
				],
				k
			) < 0
		)
			die('invalid_override: Unknown override field');
	if (
		type(local.radios) != 'array' ||
		!length(local.radios) ||
		length(local.radios) > 8 ||
		length(uniq(local.radios)) != length(local.radios) ||
		length(filter(local.radios, (r) => !safe_name(r))) ||
		(local.mesh_radio != null && !safe_name(local.mesh_radio)) ||
		(local.uplink != null && !safe_name(local.uplink))
	)
		die('invalid_override: Invalid local interface selection');
	if (
		type(local.management) != 'object' ||
		local.management.interface != 'lan' ||
		index(['dhcp', 'static'], local.management.protocol) < 0
	)
		die('invalid_override: Invalid management override');
	if (
		local.peers != null &&
		(type(local.peers) != 'array' ||
			length(local.peers) > 64 ||
			length(filter(local.peers, (m) => !match(m || '', /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/))))
	)
		die('invalid_override: Invalid mesh peer list');
	if (local.mac != null && !match(local.mac, /^02(:[0-9a-f]{2}){5}$/))
		die('invalid_override: Invalid mesh address');
	if (type(local.disable_legacy_mesh) != 'bool')
		die('invalid_override: Explicit legacy mesh takeover choice required');
	return true;
}
export function local_intent(unified, local, controller, gateway, id, control) {
	validate_overrides(local);
	return {
		...clone(unified),
		controller,
		gateway,
		name: local.name || unified.name,
		management: clone(local.management),
		wifi: { ...clone(unified.wifi), radios: clone(local.radios) },
		local: { ...clone(local), mac: mesh_mac(id) },
		...(control == null ? {} : { control: require_lease(control) })
	};
}
export function validate_extended(i) {
	let errors = [];
	function error(message) {
		push(errors, { code: 'invalid_intent', message });
	}
	if (type(i) != 'object') return [{ code: 'invalid_intent', message: 'Expected schema 2 intent' }];
	for (let k in keys(i))
		if (
			index(
				[
					'schema',
					'name',
					'controller',
					'gateway',
					'management',
					'backhaul',
					'wifi',
					'local',
					'control',
					'networks'
				],
				k
			) < 0
		)
			error('Unknown intent field: ' + k);
	let base = clone(i);
	base.schema = 1;
	base.backhaul = 'wired';
	delete base.local;
	delete base.control;
	delete base.networks;
	delete base.wifi?.roaming;
	errors = [...errors, ...validate(base)];
	try {
		validate_overrides(i.local);
	} catch (e) {
		error('Invalid local overrides');
	}
	if (i.control != null) {
		try { require_lease(i.control); if (i.controller) error('Controller cannot use an AP control lease'); }
		catch (e) { error('Invalid controller-assigned control addresses'); }
	}
	let b = i.backhaul,
		r = i.wifi?.roaming;
	if (type(b) != 'object' || index(['wired', 'wireless', 'auto', 'batman'], b.mode) < 0)
		error('Invalid backhaul mode');
	else {
		for (let k in keys(b))
			if (index(['mode', 'mesh_id', 'key', 'channel', 'htmode', 'control_vlan'], k) < 0)
				error('Unknown backhaul field');
		if (
			b.control_vlan != null &&
			(type(b.control_vlan) != 'int' || b.control_vlan < 2 || b.control_vlan > 4094)
		)
			error('Control VLAN must be 2 to 4094');
		if (b.mode != 'wired') {
			if (!valid_text(b.mesh_id, 1, 32) || !valid_text(b.key, 16, 63, true))
				error('Use a mesh ID and independent 16 to 63 character SAE secret');
			if (
				type(b.channel) != 'int' ||
				b.channel < 1 ||
				b.channel > 233 ||
				index(
					['HT20', 'HT40', 'VHT20', 'VHT40', 'VHT80', 'HE20', 'HE40', 'HE80', 'HE160'],
					b.htmode
				) < 0
			)
				error('Wireless backhaul requires a fixed channel and width');
			if (!safe_name(i.local?.mesh_radio)) error('Select a local mesh radio');
		}
	}
	if (
		type(r) != 'object' ||
		length(filter(keys(r), (k) => index(['k', 'v', 'r', 'domain', 'steering', 'policy'], k) < 0)) ||
		length(filter(['k', 'v', 'r', 'steering'], (k) => type(r[k]) != 'bool')) ||
		!match(r.domain || '', /^[0-9a-fA-F]{4}$/)
	)
		error('Invalid independent roaming policy');
	for (let message in steering_policy_errors(r?.policy)) error(message);
	if (i.networks != null && type(i.networks) != 'array') error('Networks must be an array');
	return errors;
}
export function compile_extended(i, snapshot, cap, owned, legacy, resume_steering) {
	let errors = validate_extended(i),
		virtual = clone(snapshot),
		extra = [],
		conflicts = [],
		warnings = [];
	function fail(code, message) {
		push(errors, { code, message });
	}
	if (length(errors)) return { errors, ops: [], conflicts, warnings };
	function field(config, section, option, after, reason) {
		let old = snapshot[config]?.[section];
		if (!old) {
			fail('missing_section', 'Missing section ' + config + '.' + section);
			return;
		}
		let before = old.values[option] ?? null;
		push(extra, {
			config,
			section,
			option,
			type: old.type,
			before,
			after,
			reason,
			changed: !equal(before, after)
		});
	}
	function section(config, name, type, vals, reason) {
		let before = snapshot[config]?.[name] ?? null,
			after = vals == null ? null : { type, values: vals };
		if (
			before &&
			!length(
				filter(owned || [], (o) => o.config == config && o.section == name && o.option == null)
			)
		) {
			fail('reserved_section', 'Unowned reserved section ' + name);
			return;
		}
		push(extra, {
			config,
			section: name,
			option: null,
			type,
			before,
			after,
			reason,
			changed: !equal(before, after)
		});
	}
	for (let name in keys(virtual.wireless)) {
		let s = virtual.wireless[name];
		if (s.type != 'wifi-iface' || s.values.mode != 'mesh' || s.values.disabled == '1') continue;
		if (
			name == 'mm_mesh0' &&
			length(
				filter(owned || [], (o) => o.config == 'wireless' && o.section == name && o.option == null)
			)
		) {
			s.values.disabled = '1';
			continue;
		}
		if (i.local.disable_legacy_mesh !== true) {
			fail('legacy_mesh_conflict', 'Explicitly approve legacy mesh takeover: ' + name);
			continue;
		}
		field('wireless', name, 'disabled', '1', 'explicit legacy mesh takeover');
		s.values.disabled = '1';
		push(conflicts, {
			config: 'wireless',
			section: name,
			message: 'Legacy mesh is disabled and retained for release'
		});
	}
	let base = clone(i);
	base.schema = 1;
	base.backhaul = 'wired';
	delete base.local;
	delete base.networks;
	delete base.wifi.roaming;
	delete base.control;
	let plan = legacy(base, virtual, cap, owned);
	errors = [...errors, ...plan.errors];
	conflicts = [...conflicts, ...plan.conflicts];
	warnings = filter(plan.warnings, (w) => index(w, 'No remote pairing') < 0);
	let r = i.wifi.roaming,
		b = i.backhaul;
	if (r.r && !cap.ft) {
		if (index(cap.wireless_probe_errors || [], 'ft') >= 0)
			fail('wireless_probe_unavailable', 'Wireless capability probe failed; retry the preflight');
		else fail('missing_ft', 'Installed wpad does not support 802.11r');
	}
	for (let op in plan.ops)
		if (op.config == 'wireless' && op.option == null && match(op.section, /^mm_ap_/) && op.after) {
			let v = op.after.values;
			v.ieee80211k = r.k ? '1' : '0';
			v.rrm_neighbor_report = r.k ? '1' : '0';
			v.rrm_beacon_report = r.k ? '1' : '0';
			v.bss_transition = r.v ? '1' : '0';
			v.ieee80211r = r.r ? '1' : '0';
			if (r.r) {
				v.mobility_domain = lc(r.domain);
				v.ft_over_ds = '0';
				v.ft_psk_generate_local = '1';
				v.nas_identifier = replace(i.local.mac || '', /:/g, '') + '-' + substr(op.section, 6);
				v.reassociation_deadline = '20000';
			}
			v.isolate = '0';
			op.changed = !equal(op.before, op.after);
		}
	let steering = steering_plan(i, snapshot, cap, owned, resume_steering);
	errors = [...errors, ...steering.errors]; extra = [...extra, ...steering.ops];
	conflicts = [...conflicts, ...steering.conflicts];
	let bridge = filter(
		keys(snapshot.network),
		(k) =>
			snapshot.network[k].type == 'device' &&
			snapshot.network[k].values.name == snapshot.network.lan?.values.device
	)[0];
	let ports = snapshot.network[bridge]?.values.ports;
	ports = port_tokens(ports) || [];
	let vid = b.control_vlan || 4094,
		addresses = i.control || control_addresses(
			replace(substr(i.local.mac, 3), /:/g, '') + '0000000000000000000000'
		);
	for (let name in keys(snapshot.network)) {
		let s = snapshot.network[name];
		if (
			index(['device', 'bridge-vlan'], s.type) >= 0 &&
			(int(s.values.vid || s.values.vlan) == vid ||
				match(s.values.name || s.values.ifname || '', '\\.' + vid + '$')) &&
			substr(name, 0, 3) != 'mm_'
		)
			fail('control_vlan_conflict', 'Control VLAN is already configured outside Mesh Manager');
	}
	function vlan(name, device, parent) {
		section(
			'network',
			name,
			'device',
			// Sharing the physical MAC across control/data bridges can misdirect DSA unicast traffic.
			{ name: device, type: '8021q', ifname: parent, vid: '' + vid,
				macaddr: (device == 'mm-cm' ? '0a' : '06') + substr(i.local.mac, 2) },
			'isolated control VLAN'
		);
	}
	function control(name, device, address) {
		section(
			'network',
			name,
			'interface',
			{
				proto: 'static',
				device,
				ipaddr: address,
				netmask: '255.255.0.0',
				defaultroute: '0',
				peerdns: '0'
			},
			'authenticated per-path control'
		);
	}
	if (i.controller) {
		let ctlports = [];
		for (let n = 0; n < length(ports); n++) {
			if (ports[n] == 'mm-mesh0') continue;
			if (!safe_name(ports[n])) {
				fail('unknown_port', 'Cannot map controller control port');
				continue;
			}
			let name = 'mm-cl' + n;
			vlan('mm_cl' + n + '_dev', name, ports[n]);
			push(ctlports, name);
		}
		if (b.mode != 'wired') {
			vlan('mm_cm_dev', 'mm-cm', 'mm-mesh0');
			push(ctlports, 'mm-cm');
		}
		section(
			'network',
			'mm_ctl_dev',
			'device',
			{ name: 'br-mm-ctl', type: 'bridge', ports: ctlports, stp: '1', bridge_empty: '1',
				macaddr: '0e' + substr(i.local.mac, 2) },
			'controller control bridge'
		);
		control('mm_ctl', 'br-mm-ctl', '169.254.254.1');
		if (b.mode == 'wired' && snapshot.network.mm_cm_dev)
			section('network', 'mm_cm_dev', 'device', null, 'remove obsolete wireless control');
	} else if (safe_name(i.local.uplink)) {
		vlan('mm_cw_dev', 'mm-cw', i.local.uplink);
		control('mm_cw', 'mm-cw', addresses.wired);
		if (b.mode != 'wired') {
			vlan('mm_cm_dev', 'mm-cm', 'mm-mesh0');
			control('mm_cm', 'mm-cm', addresses.wireless);
		}
		else {
			if (snapshot.network.mm_cm_dev)
				section('network', 'mm_cm_dev', 'device', null, 'remove obsolete wireless control');
			if (snapshot.network.mm_cm)
				section('network', 'mm_cm', 'interface', null, 'remove obsolete wireless control');
		}
	}
	section(
		'firewall',
		'mm_control',
		'zone',
		{
			name: 'mm_control',
			network: i.controller ? ['mm_ctl'] : b.mode == 'wired' ? ['mm_cw'] : ['mm_cw', 'mm_cm'],
			input: 'REJECT',
			output: 'ACCEPT',
			forward: 'REJECT',
			masq: '0',
			masq6: '0'
		},
		'isolated management control zone'
	);
	if (i.controller)
		section(
			'firewall',
			'mm_control_tls',
			'rule',
			{
				name: 'Mesh Manager authenticated control',
				src: 'mm_control',
				proto: 'tcp',
				dest_port: '37901',
				target: 'ACCEPT'
			},
			'mutually authenticated control only'
		);
	if (r.steering || length(filter(owned || [], op => op.config=='firewall' && op.section=='mm_usteer')))
		section('firewall','mm_usteer','rule',r.steering ? {
			name:'Mesh Manager roaming coordination',src:'mm_control',proto:'udp',dest_port:'16720',family:'ipv4',target:'ACCEPT'
		} : null,'roaming coordination on isolated management interfaces');
	if (!i.controller) {
		let uplink = i.local.uplink,
			wan = snapshot.network.wan,
			wan_bridge = filter(keys(snapshot.network), (name) => {
				let device = snapshot.network[name];
				return device.type == 'device' && device.values.type == 'bridge' &&
					device.values.name == wan?.values.device;
			})[0];
		let wan_ports = snapshot.network[wan_bridge]?.values.ports;
		wan_ports = port_tokens(wan_ports) || [];
		let bridge_uplink = wan_bridge && (length(wan_ports) == 1 && wan_ports[0] == uplink ||
			!length(wan_ports) && length(filter(owned || [], (op) =>
				op.config == 'network' && op.section == wan_bridge && op.option == 'ports' &&
				op.after == null && equal(port_tokens(op.before), [uplink]))));
		let standard_wan = wan && (wan.values.device == uplink || bridge_uplink),
			wan6 = snapshot.network.wan6,
			standard_wan6 = standard_wan && wan6 &&
				index(['@wan', uplink, wan.values.device], wan6.values.device) >= 0,
			allowed = ['lan', bridge];
		if (standard_wan) push(allowed, 'wan');
		if (bridge_uplink) push(allowed, wan_bridge);
		if (standard_wan6) push(allowed, 'wan6');
		for (let op in owned || [])
			if (op.config == 'network' && op.option == null && op.after &&
				equal(snapshot.network[op.section], op.after)) push(allowed, op.section);
		errors = [...errors, ...uplink_conflicts(snapshot, uplink, allowed)];
		if (!safe_name(uplink) || uplink == snapshot.network.lan?.values.device)
			fail('missing_uplink', 'AP needs an explicit physical uplink');
		else {
			if (standard_wan) {
				if (bridge_uplink)
					field('network', wan_bridge, 'ports', null, 'isolate original single-port WAN bridge');
				field('network', 'wan', 'proto', 'none', 'AP WAN becomes bridge uplink');
				field('network', 'wan', 'auto', '0', 'disable AP WAN L3');
				if (standard_wan6) {
					field('network', 'wan6', 'proto', 'none', 'disable AP WAN6');
					field('network', 'wan6', 'auto', '0', 'disable AP WAN6 L3');
				}
				push(conflicts, {
					config: 'network',
					section: 'wan',
					message: 'AP WAN becomes managed uplink; original settings retained for release'
				});
			} else if (index(ports, uplink) < 0 && !length(filter(owned || [], (op) =>
				op.config == 'network' && op.section == 'mm_wired_link' && op.option == null &&
				op.after?.type == 'interface' && op.after.values.proto == 'none' &&
				op.after.values.device == uplink && equal(snapshot.network.mm_wired_link, op.after))))
				fail('uplink_conflict', 'Selected AP uplink is not in LAN or standard WAN');
			ports = filter(ports, (p) => p != uplink && p != 'mm-mesh0');
			if (b.mode == 'wired') push(ports, uplink);
			field('network', bridge, 'ports', uniq(ports), 'single active data path');
			if (b.mode != 'wired')
				section(
					'network',
					'mm_wired_link',
					'interface',
					{ proto: 'none', device: uplink },
					'isolated wired link'
				);
			else if (snapshot.network.mm_wired_link)
				section('network', 'mm_wired_link', 'interface', null, 'release isolated wired link');
		}
		if (i.management.protocol == 'static' && i.local.gateway) {
			field('network', 'lan', 'gateway', i.local.gateway, 'bridge gateway override');
			field('network', 'lan', 'dns', [i.local.gateway], 'bridge DNS override');
		}
	}
	if (b.mode != 'wired') {
		let incompatible=cap.wireless_control_status=='incompatible';
		let probe_failed = length(filter(cap.wireless_probe_errors || [], name => index(['mesh', 'sae', 'link_flags'], name) >= 0));
		if (incompatible)
			fail('wireless_control_incompatible', 'Installed wifi-scripts rejects successful interface flag acknowledgements; repair the firmware components before applying wireless backhaul');
		else if (probe_failed)
			fail('wireless_probe_unavailable', 'Wireless capability probe failed; retry the preflight');
		else if (!cap.mesh || !cap.sae || !cap.mesh_control)
			fail('missing_mesh', 'Verified mesh/SAE wpad with local control API is required');
		if (!incompatible && !probe_failed && !cap.mesh_acl)
			fail('missing_mesh_acl', 'wpa_supplicant must support explicit 802.11s peer authorization');
		let radio = i.local.mesh_radio;
		if (snapshot.wireless[radio]?.type != 'wifi-device')
			fail('unknown_radio', 'Mesh radio not present');
		else {
			let mode = backhaul_mode(cap.radios, radio, b.htmode);
			if (mode.error == 'radio_capability_unknown')
				fail(mode.error, 'Selected radio capabilities are unknown; retry the preflight');
			else if (mode.error)
				fail(mode.error, 'Selected radio does not support the requested backhaul width');
			else {
				field('wireless', radio, 'channel', '' + b.channel, 'coordinated backhaul channel');
				field('wireless', radio, 'htmode', mode.htmode, 'coordinated width');
				field('wireless', radio, 'disabled', '0', 'enable mesh radio');
			}
		}
		if (b.mode == 'batman') fail('missing_backend', 'batman backend requires separate preflight');
		section(
			'network',
			'mm_mesh_link',
			'interface',
			{ proto: 'none', device: 'mm-mesh0' },
			'isolated wireless link'
		);
		section(
			'wireless',
			'mm_mesh0',
			'wifi-iface',
			{
				device: radio,
				ifname: 'mm-mesh0',
				mode: 'mesh',
				network: 'mm_mesh_link',
				mesh_id: b.mesh_id,
				encryption: 'sae',
				key: b.key,
				macaddr: i.local.mac,
				disabled: '0',
				mesh_auto_open_plinks: '0',
				mesh_fwding: i.controller ? '1' : '0',
				mesh_ttl: '2',
				mesh_hwmp_rootmode: '0',
				mesh_gate_announcements: '0'
			},
			'authenticated star-only mesh'
		);
	} else if (
		snapshot.wireless.mm_mesh0 &&
		length(
			filter(
				owned || [],
				(o) => o.config == 'wireless' && o.section == 'mm_mesh0' && o.option == null
			)
		)
	)
		section('wireless', 'mm_mesh0', 'wifi-iface', null, 'remove managed mesh');
	if (b.mode == 'wired') {
		for (let name in ['mm_mesh_link'])
			if (snapshot.network[name])
				section('network', name, 'interface', null, 'remove obsolete mesh link');
		// Drop the backhaul radio constraint using its first takeover value, not the last intent.
		for (let owner in owned || []) {
			if (owner.config != 'wireless' ||
				!(owner.option == 'channel' && owner.reason == 'coordinated backhaul channel' ||
					owner.option == 'htmode' && owner.reason == 'coordinated width')) continue;
			let current = snapshot.wireless?.[owner.section];
			if (owner.type != 'wifi-device' || current?.type != owner.type ||
				!equal(current.values[owner.option] ?? null, owner.after)) {
				fail('ownership_conflict', 'Managed radio tuning changed before restoration: ' + owner.section + '.' + owner.option);
				continue;
			}
			field('wireless', owner.section, owner.option, clone(owner.before), 'restore local radio tuning');
		}
	}
	if (length(i.networks || []))
		fail('network_backend', 'Additional networks require VLAN backend preflight');
	let ops = [];
	for (let op in [...plan.ops, ...extra]) {
		let same = filter(
			ops,
			(o) => o.config == op.config && o.section == op.section && o.option == op.option
		)[0];
		if (same) {
			same.after = op.after;
			same.changed = !equal(same.before, same.after);
			same.reason = op.reason;
		} else push(ops, op);
	}
	return { errors, ops: length(errors) ? [] : ops, conflicts, warnings, dangerous: true };
}
