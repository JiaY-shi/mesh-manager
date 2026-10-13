// SPDX-License-Identifier: GPL-2.0-only
'use strict';

export function port_tokens(value) {
	if (value == null) return [];
	let result = [];
	for (let item in type(value) == 'array' ? value : [value]) {
		if (type(item) != 'string') return null;
		for (let token in split(item, /[ \t\r\n]+/)) if (length(token)) push(result, token);
	}
	return uniq(result);
}

// Resolve bridge and VLAN ancestry before changing a physical data path.
export function device_path(snapshot, name, parents) {
	if (type(name) != 'string' || !match(name, /^[a-zA-Z0-9_.-]{1,15}$/) ||
		index(parents, name) >= 0 || length(parents) >= 16) return null;
	let sections = filter(keys(snapshot.network || {}),
		(k) => snapshot.network[k].type == 'device' && snapshot.network[k].values.name == name);
	if (length(sections) > 1) return null;
	let values = snapshot.network?.[sections[0]]?.values, children = [];
	if (values?.type == 'bridge') {
		children = port_tokens(values.ports);
		if (!length(children || [])) return null;
	} else if (index(['8021q', '8021ad'], values?.type) >= 0) {
		children = port_tokens(values.ifname);
		if (length(children || []) != 1) return null;
	} else {
		if (values && ((values.type != null && values.type != '') ||
			values.ifname != null || values.ports != null)) return null;
		if (index(name, '.') >= 0) {
			let vlan = match(name, /^(.+)\.([0-9]{1,4})$/);
			if (!vlan || int(vlan[2]) > 4094) return null;
			children = [vlan[1]];
		}
	}
	let path = [name];
	for (let child in children) {
		let lower = device_path(snapshot, child, [...parents, name]);
		if (lower == null) return null;
		path = [...path, ...lower];
	}
	return uniq(path);
}

export function lan_bridge(snapshot) {
	let name = snapshot.network?.lan?.values?.device;
	if (type(name) != 'string' || !match(name, /^[a-zA-Z0-9_.-]{1,15}$/)) return null;
	let sections = filter(values(snapshot.network || {}),
		(s) => s.type == 'device' && s.values.name == name);
	return length(sections) == 1 && sections[0].values.type == 'bridge' ? name : null;
}

function interface_path(snapshot, device, parents) {
	if (type(device) != 'string') return null;
	if (substr(device, 0, 1) != '@') return device_path(snapshot, device, []);
	if (index(parents, device) >= 0 || length(parents) >= 16) return null;
	let section = snapshot.network?.[substr(device, 1)];
	if (section?.type != 'interface') return null;
	return interface_path(snapshot, section.values.device, [...parents, device]);
}

export function uplink_conflicts(snapshot, uplink, allowed) {
	let errors = [], target = device_path(snapshot, uplink, []);
	if (target == null) return [{ code: 'uplink_topology_unknown', section: uplink,
		message: 'Cannot resolve the selected AP uplink device topology: ' + uplink }];
	for (let name in keys(snapshot.network || {})) {
		if (index(allowed, name) >= 0) continue;
		let section = snapshot.network[name], v = section.values, paths = [];
		if (section.type == 'interface') {
			if (v.device != null) paths = [interface_path(snapshot, v.device, [])];
			else if (v.ifname != null) {
				let devices = port_tokens(v.ifname);
				paths = devices == null ? [null] : map(devices, (device) => interface_path(snapshot, device, []));
			}
		} else if (section.type == 'device') {
			if (v.type || v.ifname != null || v.ports != null)
				paths = [device_path(snapshot, v.name, [])];
		} else if (section.type == 'bridge-vlan') {
			let devices = port_tokens(v.device);
			paths = devices == null ? [null] : map(devices, (device) => device_path(snapshot, device, []));
		}
		if (length(filter(paths, (path) => path == null)))
			push(errors, { code: 'uplink_topology_unknown', section: name,
				message: 'Cannot verify whether another network configuration shares the AP uplink: ' + name });
		else if (length(filter(paths, (path) => length(filter(path, (device) => index(target, device) >= 0)))))
			push(errors, { code: 'uplink_shared', section: name,
				message: 'AP uplink is also used by another network configuration: ' + name });
	}
	return errors;
}
