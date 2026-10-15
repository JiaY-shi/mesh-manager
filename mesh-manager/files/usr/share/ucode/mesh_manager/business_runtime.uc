// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import { cursor } from 'uci';
import { equal } from './model.uc';
import { extension_bridge, extension_device } from './network_extensions.uc';
import { reconcile } from './backhaul.uc';

function raw_section(c, name) {
	let raw = c.get_all('network', name);
	if (!raw) return null;
	let values = {};
	for (let key in keys(raw)) if (substr(key, 0, 1) != '.') values[key] = raw[key];
	return { type: raw['.type'], values };
}

// Business traffic follows the same removal-before-addition decision as LAN.
// Every link must still match the transaction's whole-section UCI ownership.
export function reconcile_business(journal, intent, active, io) {
	if (intent.controller || intent.data_root === true) return;
	if (index(['wired', 'wireless', 'none'], active) < 0) die('invalid_path: Invalid business uplink');
	let c = cursor('/etc/config', '/var/run/mesh-manager-uci', '');
	if (!c.load('network')) die('invalid_topology: Business network inventory is unavailable');
	let owners = journal.active?.status == 'awaiting_confirm' ?
		[...(journal.active.ops || []), ...(journal.active.expected_owned || [])] : journal.owned || [];
	for (let n in intent.networks || []) {
		if (!n.enabled) continue;
		let bridge = extension_bridge(n.id), links = { wired: extension_device(n.id, 'w'), wireless: extension_device(n.id, 'm') };
		let names = ['mm_' + n.id + '_dev', 'mm_' + n.id + '_w'];
		if (intent.backhaul.mode != 'wired') push(names, 'mm_' + n.id + '_m');
		for (let name in names) {
			let current = raw_section(c, name), owned = filter(owners, o => o.config == 'network' &&
				o.section == name && o.option == null && o.after != null && equal(current, o.after))[0];
			if (!owned || current.type != 'device' || !fs.access('/sys/class/net/' + current.values.name) ||
				trim(fs.readfile('/sys/class/net/' + current.values.name + '/address') || '') != current.values.macaddr)
				die('ownership_conflict: Business bridge or VLAN no longer matches its owner');
			if (current.values.type == '8021q' &&
				!fs.readlink('/sys/class/net/' + current.values.name + '/lower_' + current.values.ifname))
				die('ownership_conflict: Business VLAN parent changed');
		}
		if (intent.backhaul.mode == 'wired') {
			let current = io.master(links.wired);
			if (current && current != bridge) die('ownership_conflict: Business VLAN belongs to another bridge');
			if (active == 'wired' && !current) io.attach(links.wired, bridge);
			if (active == 'none' && current == bridge) io.detach(links.wired, bridge);
		} else {
			for (let name in values(links))
				if (io.master(name) != null && io.master(name) != bridge)
					die('ownership_conflict: Business VLAN belongs to another bridge');
			reconcile({ master: io.master, detach: name => io.detach(name, bridge),
				attach: (name, target) => io.attach(name, target) }, active, bridge, links, n.id);
		}
	}
}
