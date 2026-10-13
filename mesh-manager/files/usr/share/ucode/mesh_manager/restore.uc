// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone } from './model.uc';

export function restore_checks(snapshot, ops, intent, carrier) {
	let restored = clone(snapshot), errors = [];
	for (let op in ops) {
		if (op.option == null) {
			if (op.after == null) delete restored[op.config]?.[op.section];
			else restored[op.config][op.section] = clone(op.after);
		} else if (restored[op.config]?.[op.section]) {
			if (op.after == null) delete restored[op.config][op.section].values[op.option];
			else restored[op.config][op.section].values[op.option] = clone(op.after);
		}
	}
	if (intent?.controller && intent.gateway != 'bridge') return errors;
	if (!intent?.controller && !intent?.local?.uplink) return errors;
	let uplink = intent?.local?.uplink, net = restored.network || {};
	function ports(device, visited) {
		if (!device || visited[device]) return null;
		visited[device] = true;
		let section = filter(values(net), (s) => s.type == 'device' && s.values.name == device)[0];
		if (!section) return match(device, /^[a-zA-Z0-9_-]{1,15}$/) ? [device] : null;
		if (section.values.type != 'bridge') return null;
		let list = section.values.ports;
		list = type(list) == 'array' ? list : type(list) == 'string' ? split(list, ' ') : [];
		let result = [];
		for (let port in list) {
			let nested = ports(port, clone(visited));
			if (!nested) return null;
			result = [...result, ...nested];
		}
		return result;
	}
	for (let dhcp in values(restored.dhcp || {})) {
		if (dhcp.type != 'dhcp') continue;
		let v = dhcp.values;
		let ipv6_active = false;
		// odhcpd enables non-disabled IPv6 modes independently of IPv4 ignore.
		for (let option in keys(v))
			if (index(['ra', 'dhcpv6', 'ndp'], option) >= 0 && v[option] !== 'disabled') ipv6_active = true;
		if (v.ignore == '1' && !ipv6_active) continue;
		let iface = net[v.interface]?.values, members = ports(iface?.device, {});
		if (!members) {
			push(errors, { code: 'restore_topology_unknown',
				message: 'Cannot verify the restored DHCP network; inspect wiring before disabling Mesh' });
			continue;
		}
		let upstream = intent.controller ? members : index(members, uplink) >= 0 ? [uplink] : [];
		for (let port in upstream) {
			let link = carrier(port);
			if (link != '0') push(errors, { code: link == '1' ? 'restore_dhcp_conflict' : 'restore_link_unknown',
				message: 'Restoring DHCP on the connected uplink ' + port +
					' is unsafe; disconnect it or move the cable to the original WAN port first' });
		}
	}
	return errors;
}
