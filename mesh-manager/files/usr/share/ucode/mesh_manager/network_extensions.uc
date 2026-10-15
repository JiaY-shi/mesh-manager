// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal, valid_text, ipv4 } from './model.uc';
import { port_tokens } from './topology.uc';

export const NETWORK_IDS = ['guest'];

function fields(value, allowed) {
	return type(value) == 'object' && !length(filter(keys(value), k => index(allowed, k) < 0));
}
function number(value, lo, hi) { return type(value) == 'int' && value >= lo && value <= hi; }
function address(value) {
	if (type(value) != 'string') return null;
	let parts = split(value, '/');
	if (length(parts) != 2 || parts[1] != '24' || !ipv4(parts[0])) return null;
	let octets = map(split(parts[0], '.'), value => int(value));
	if (!(octets[0] == 10 || octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 ||
		octets[0] == 192 && octets[1] == 168) || octets[3] != 1) return null;
	return { ip: parts[0], prefix: join('.', slice(octets, 0, 3)) };
}
export function network_errors(networks) {
	let errors = [], seen = [];
	function fail(text) { push(errors, text); }
	if (networks == null) return errors;
	if (type(networks) != 'array' || length(networks) > 1) return ['Choose at most one Guest network'];
	for (let n in networks) {
		if (!fields(n, ['id', 'enabled', 'ssid', 'key', 'encryption', 'vlan', 'subnet', 'isolate', 'internet', 'lan_access', 'access']) ||
			index(NETWORK_IDS, n.id) < 0 || index(seen, n.id) >= 0) {
			fail('Only the Guest additional network is supported'); continue;
		}
		push(seen, n.id);
		if (type(n.enabled) != 'bool' || type(n.isolate) != 'bool' || type(n.internet) != 'bool' ||
			n.lan_access != null && type(n.lan_access) != 'bool')
			fail('Additional network switches must be boolean');
		if (n.vlan != 'auto' && !number(n.vlan, 2, 4093)) fail('Business VLAN must be auto or 2 to 4093');
		if (n.subnet != 'auto' && !address(n.subnet)) fail('Use auto or a private /24 subnet with gateway address .1');
		if (n.enabled && (!valid_text(n.ssid, 1, 32) || !valid_text(n.key, 8, 63, true) ||
			index(['psk2', 'sae-mixed'], n.encryption) < 0)) fail('Additional networks need an SSID and an independent printable passphrase');
		if (type(n.access) != 'array' || length(n.access) > 8) { fail('At most eight explicit access exceptions are supported'); continue; }
		let exceptions = [];
		for (let rule in n.access) {
			if (!fields(rule, ['from', 'protocol', 'ports']) || rule.from != 'lan' ||
				index(['tcp', 'udp'], rule.protocol) < 0 || type(rule.ports) != 'array' || !length(rule.ports) ||
				length(rule.ports) > 16 || length(uniq(rule.ports)) != length(rule.ports) ||
				length(filter(rule.ports, p => !number(p, 1, 65535)))) {
				fail('Access exceptions require LAN, TCP or UDP, and one to sixteen distinct ports'); continue;
			}
			let key = rule.protocol + ':' + join(',', sort(clone(rule.ports)));
			if (index(exceptions, key) >= 0) fail('Duplicate access exception');
			push(exceptions, key);
		}
	}
	return errors;
}

function ipv4_number(value) {
	if (!ipv4(value)) return null;
	let result = 0;
	for (let item in split(value, '.')) result = result * 256 + int(item);
	return result;
}
function overlaps(a, prefix, b, other_prefix) {
	let size = 1;
	for (let bit = 0; bit < 32 - min(prefix, other_prefix); bit++) size *= 2;
	return int(a / size) == int(b / size);
}
// netifd also owns addresses learned through DHCP, absent from UCI. Never
// turn an incomplete/malformed inventory into an empty conflict baseline.
export function network_inventory(raw) {
	let unavailable={status:'unavailable',items:[]},items=[],seen=[];
	if (type(raw)!='object' || raw.truncated===true || type(raw.interface)!='array' || !length(raw.interface) || length(raw.interface)>128 ||
		length(sprintf('%J',raw))>262144) return unavailable;
	for (let row in raw.interface) {
		if (type(row)!='object' || type(row.interface)!='string' ||
			match(row.interface,/^[A-Za-z0-9_]{1,64}$/)?.[0]!==row.interface || index(seen,row.interface)>=0)
			return unavailable;
		let addresses=row['ipv4-address'] ?? [],values=[];
		if (type(addresses)!='array' || length(addresses)>32) return unavailable;
		for (let address in addresses) {
			if (type(address)!='object' || !ipv4(address.address) || !number(address.mask,0,32)) return unavailable;
			push(values,{ip:ipv4_number(address.address),prefix:address.mask});
		}
		push(seen,row.interface);push(items,{interface:row.interface,addresses:values});
	}
	return {status:'complete',items};
}
function occupied(snapshot, owned, inventory) {
	let vlans = [], ranges = [];
	for (let name in keys(snapshot.network || {})) {
		let section = snapshot.network[name], v = section.values;
		// The original pre-takeover value remains the conflict baseline.
		let owner = filter(owned || [], o => o.config == 'network' && o.section == name && o.option == null)[0];
		if (owner && equal(section, owner.after)) continue;
		let vid = int(v.vid || v.vlan);
		if (vid >= 1 && vid <= 4094) push(vlans, vid);
		for (let link in [...(port_tokens(v.ports) || []), ...(port_tokens(v.device) || []), ...(port_tokens(v.ifname) || []), v.name]) {
			let suffix = match(link || '', /\.([0-9]{1,4})$/);
			if (suffix && int(suffix[1]) >= 1 && int(suffix[1]) <= 4094) push(vlans, int(suffix[1]));
		}
		for (let value in type(v.ipaddr) == 'array' ? v.ipaddr : [v.ipaddr]) {
			if (type(value) != 'string') continue;
			let parts = split(value, '/'), ip = ipv4_number(parts[0]), mask = ipv4_number(v.netmask), prefix = 32;
			if (length(parts) == 2 && match(parts[1], /^[0-9]{1,2}$/) && int(parts[1]) <= 32) prefix = int(parts[1]);
			else if (mask != null) {
				prefix = 0;
				for (let bit = 0; bit < 32; bit++) { if (mask % 2) prefix++; mask = int(mask / 2); }
			}
			if (ip != null) push(ranges, { ip, prefix });
		}
	}
	for (let row in inventory?.status=='complete' ? inventory.items : []) {
		let owner=filter(owned || [],o=>o.config=='network' && o.section==row.interface && o.option==null)[0];
		if (owner && equal(snapshot.network?.[row.interface] ?? null,owner.after)) continue;
		for (let range in row.addresses) push(ranges,clone(range));
	}
	return { vlans, ranges };
}

// Root freezes concrete VLANs/subnets before dispatching all-node previews.
// Every AP still checks its own external VLANs and subnets independently.
export function resolve_networks(intent, snapshot, owned) {
	let inventory=snapshot.business_inventory;
	if (inventory!=null && inventory.status!='complete')
		die('network_inventory_unavailable: Fresh network inventory is required for Guest configuration');
	let result = clone(intent), used = occupied(snapshot, owned,inventory);
	push(used.vlans, intent.backhaul?.control_vlan || 4094);
	for (let n in result.networks || []) {
		if (!n.enabled) continue;
		if (n.vlan == 'auto') {
			let candidate = 100;
			while (index(used.vlans, candidate) >= 0 && candidate <= 4093) candidate++;
			if (candidate > 4093) die('network_conflict: No free business VLAN is available');
			n.vlan = candidate;
		}
		push(used.vlans, n.vlan);
		if (n.subnet == 'auto') {
			let selected = null, bases = [];
			for (let block = 90; block < 255; block++) push(bases, '10.' + block);
			for (let block = 16; block <= 31; block++) push(bases, '172.' + block);
			push(bases, '192.168');
			for (let base in bases) {
				let block_ip = ipv4_number(base + '.0.1');
				if (length(filter(used.ranges, r => r.prefix <= 16 && overlaps(block_ip, 16, r.ip, r.prefix)))) continue;
				for (let octet = 10; octet < 250; octet++) {
					let candidate = base + '.' + octet + '.1', ip = ipv4_number(candidate);
					if (!length(filter(used.ranges, r => overlaps(ip, 24, r.ip, r.prefix)))) { selected = candidate + '/24'; break; }
				}
				if (selected) break;
			}
			if (!selected) die('network_conflict: No free private business subnet is available');
			n.subnet = selected;
		}
		let subnet = address(n.subnet);
		if (subnet) push(used.ranges, { ip: ipv4_number(subnet.ip), prefix: 24 });
	}
	return result;
}

export function extension_bridge(id) {
	if (id!='guest') die('invalid_network: Only the Guest additional network is supported');
	return 'br-mm-g';
}
export function extension_device(id, path) {
	if (id!='guest') die('invalid_network: Only the Guest additional network is supported');
	return 'mm-g' + path;
}

export function network_plan(intent, snapshot, cap, owned, ports) {
	let errors = map(network_errors(intent.networks), message => ({ code: 'invalid_network', message })),
		ops = [], warnings = [], wanted = {}, used = occupied(snapshot, owned,cap.business_inventory), ids = [], ranges = [];
	if (length(errors)) return { errors, ops, warnings };
	function fail(code, message) { push(errors, { code, message }); }
	if (length(filter(intent.networks || [],n=>n.enabled)) && cap.business_inventory!=null && cap.business_inventory.status!='complete')
		fail('network_inventory_unavailable','Fresh network inventory is required for Guest configuration');
	function section(config, name, type, values, reason) {
		let before = snapshot[config]?.[name] ?? null, after = values == null ? null : { type, values },
			owner = filter(owned || [], o => o.config == config && o.section == name && o.option == null)[0];
		wanted[config + ':' + name] = true;
		if (before && (!owner || !equal(before, owner.after))) {
			fail('ownership_conflict', 'Additional network section has external changes: ' + config + '.' + name); return;
		}
		push(ops, { config, section: name, option: null, type, before, after, reason, changed: !equal(before, after) });
	}
	let gateway = intent.gateway == 'router';
	for (let n in intent.networks || []) {
		if (!n.enabled) continue;
		if (!cap.hostapd) fail('missing_dependency', 'A working hostapd/wpad installation is required');
		if (n.encryption == 'sae-mixed' && !cap.sae)
			fail(index(cap.wireless_probe_errors || [], 'sae') >= 0 ? 'wireless_probe_unavailable' : 'missing_sae',
				'SAE capability has not been verified');
		if (!number(n.vlan, 2, 4093) || !address(n.subnet)) {
			fail('network_unresolved', 'Automatic VLANs and subnets must be resolved by the controller preview'); continue;
		}
		if (n.vlan == (intent.backhaul?.control_vlan || 4094) || index(used.vlans, n.vlan) >= 0 || index(ids, n.vlan) >= 0)
			fail('network_conflict', 'Business VLAN conflicts with another network or the control VLAN');
		push(ids, n.vlan);
		let subnet = address(n.subnet), ip = ipv4_number(subnet.ip);
		if (length(filter([...used.ranges, ...ranges], r => overlaps(ip, 24, r.ip, r.prefix))))
			fail('network_conflict', 'Business subnet overlaps another configured network');
		push(ranges, { ip, prefix: 24 });
		if (intent.controller && !gateway)
			fail('network_gateway_required', 'A managed routing gateway is required for the automatic Guest network');
		let name = 'mm_' + n.id, bridge = extension_bridge(n.id), bridge_ports = [];
		let parents = intent.controller ? filter(ports, p => p != 'mm-mesh0') : [intent.local.uplink];
		if (intent.backhaul.mode != 'wired') push(parents, 'mm-mesh0');
		for (let parent in uniq(parents)) {
			if (!match(parent || '', /^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/)) {
				fail('unsupported_topology', 'Cannot map the business VLAN transport'); continue;
			}
			let path = parent == 'mm-mesh0' ? 'm' : intent.controller ? 'l' + index(parents, parent) : 'w',
				device = extension_device(n.id, path);
			section('network', name + '_' + path, 'device', { name: device, type: '8021q', ifname: parent,
				vid: '' + n.vlan, macaddr: '12' + substr(intent.local.mac, 2) }, 'business VLAN transport');
			if (intent.controller || intent.backhaul.mode == 'wired') push(bridge_ports, device);
			else section('network', name + '_' + path + '_link', 'interface', { proto: 'none', device }, 'isolated business uplink');
		}
		let device_values = { name: bridge, type: 'bridge', bridge_empty: '1', stp: '1',
			macaddr: '1a' + substr(intent.local.mac, 2) };
		if (length(bridge_ports)) device_values.ports = bridge_ports;
		section('network', name + '_dev', 'device', device_values, 'isolated business bridge');
		section('network', name, 'interface', gateway ? { proto: 'static', device: bridge, ipaddr: subnet.ip,
			netmask: '255.255.255.0', delegate: '0', defaultroute: '0', peerdns: '0', ipv6: '0' } :
			{ proto: 'none', device: bridge, delegate: '0', ipv6: '0' }, 'business network gateway or transparent AP');
		if (gateway) {
			section('dhcp', name, 'dhcp', { interface: name, start: '100', limit: '100', leasetime: '2h',
				ignore: '0', dhcpv4: 'server', ra: 'disabled', dhcpv6: 'disabled', ndp: 'disabled' }, 'business DHCP on gateway only');
			section('firewall', name, 'zone', { name, network: [name], input: 'REJECT', output: 'ACCEPT',
				forward: 'REJECT', masq: '0', masq6: '0' }, 'isolate business networks from LAN and one another');
			for (let service in [{ id: 'dns', protocol: ['tcp', 'udp'], port: '53' }, { id: 'dhcp', protocol: ['udp'], port: '67' }])
				section('firewall', name + '_' + service.id, 'rule', { name: 'Mesh ' + n.id + ' ' + service.id,
					src: name, proto: service.protocol, dest_port: service.port, family: 'ipv4', target: 'ACCEPT' }, 'business DHCP and DNS only');
			if (n.internet) section('firewall', name + '_wan', 'forwarding', { src: name, dest: 'wan' }, 'approved business Internet access');
			if (n.lan_access === true) {
				section('firewall', name + '_lan_out', 'forwarding', { src: name, dest: 'lan' }, 'approved business to LAN access');
				section('firewall', name + '_lan_in', 'forwarding', { src: 'lan', dest: name }, 'approved LAN to business access');
				section('firewall', name + '_lan_router', 'rule', { name: 'Mesh ' + n.id + ' LAN gateway access',
					src: name, dest_ip: intent.management.address, proto: 'all', family: 'ipv4', target: 'ACCEPT' },
					'approved business to main LAN gateway address');
			}
			for (let index = 0; index < length(n.access); index++) {
				let rule = n.access[index];
				section('firewall', name + '_access' + index, 'rule', { name: 'Mesh ' + n.id + ' access ' + index,
					src: 'lan', dest: name, proto: rule.protocol, dest_port: join(' ', rule.ports), family: 'ipv4', target: 'ACCEPT' }, 'explicit LAN to business service exception');
			}
		}
		for (let radio in intent.wifi.radios || []) {
			if (snapshot.wireless?.[radio]?.type != 'wifi-device') { fail('unknown_radio', 'Additional network radio is missing'); continue; }
			if (snapshot.wireless[radio].values.band == '6g' && n.encryption != 'sae-mixed') {
				fail('six_ghz_security', '6 GHz business networks require WPA3-capable encryption'); continue;
			}
			section('wireless', name + '_' + radio, 'wifi-iface', { device: radio, mode: 'ap', network: name,
				ssid: n.ssid, encryption: snapshot.wireless[radio].values.band == '6g' ? 'sae' : n.encryption,
				key: n.key, disabled: '0', isolate: n.isolate ? '1' : '0',
				...(snapshot.wireless[radio].values.band == '6g' ? { ieee80211w: '2', sae_pwe: '1' } : {}) }, 'managed isolated business AP');
		}
	}
	for (let owner in owned || []) {
		if (owner.option != null || !match(owner.section, /^mm_(guest|iot)(_|$)/) || wanted[owner.config + ':' + owner.section]) continue;
		let before = snapshot[owner.config]?.[owner.section] ?? null;
		if (!equal(before, owner.after)) { fail('ownership_conflict', 'Business configuration changed before removal'); continue; }
		section(owner.config, owner.section, owner.type, null, 'remove obsolete managed business network');
	}
	return { errors, ops: length(errors) ? [] : ops, warnings };
}
