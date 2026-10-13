// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { equal } from './model.uc';
import { lan_bridge } from './topology.uc';

export function active_backhaul_intent(state) {
	if (!state || state.schema != 1) return null;
	let active = state.active;
	if (active?.status == 'awaiting_confirm' && active.intent?.schema == 2)
		return { intent: active.intent, committed: false };
	if (active && index(['committed', 'rolled_back', 'expired'], active.status) < 0)
		return null;
	return state.intent?.schema == 2 ? { intent: state.intent, committed: true } : null;
}

export function mesh_network_id(reply, mesh_id) {
	if (type(reply) != 'string' || type(mesh_id) != 'string') return null;
	let found = [];
	for (let line in split(reply, '\n')) {
		let fields = split(line, '\t');
		if (length(fields) < 4 || !match(fields[0], /^[0-9]+$/) ||
			fields[1] != mesh_id || index(fields[3], '[CURRENT]') < 0)
			continue;
		push(found, fields[0]);
	}
	return length(found) == 1 ? found[0] : null;
}

export function mesh_acl_enabled(bus, ifname, mesh_id) {
	if (!bus || ifname != 'mm-mesh0') return false;
	let object = 'wpa_supplicant.' + ifname,
		list = bus.call(object, 'control', { command: 'LIST_NETWORKS' }),
		id = mesh_network_id(list?.result, mesh_id);
	if (id == null) return false;
	let setting = bus.call(object, 'control', {
		command: 'GET_NETWORK ' + id + ' no_auto_peer'
	});
	return trim(setting?.result || '') == '1';
}

export function ensure_mesh_acl(bus, ifname, mesh_id) {
	if (!bus || ifname != 'mm-mesh0') return false;
	let object = 'wpa_supplicant.' + ifname;
	let list = bus.call(object, 'control', { command: 'LIST_NETWORKS' });
	let id = mesh_network_id(list?.result, mesh_id);
	if (id == null) return false;
	if (mesh_acl_enabled(bus, ifname, mesh_id)) return true;
	let set = bus.call(object, 'control', {
		command: 'SET_NETWORK ' + id + ' no_auto_peer 1'
	});
	return trim(set?.result || '') == 'OK' && mesh_acl_enabled(bus, ifname, mesh_id);
}

export function mesh_stations(bus, ifname) {
	if (!bus || ifname != 'mm-mesh0') die('invalid_peer: Unsafe station enumeration');
	let stations = [], command = 'STA-FIRST';
	for (let n = 0; n < 64; n++) {
		let response = bus.call('wpa_supplicant.' + ifname, 'control', { command });
		let result = response?.result;
		if (result == '' || result == 'FAIL\n' || result == 'FAIL') return stations;
		let mac = match(result || '', /^([0-9a-f]{2}(:[0-9a-f]{2}){5})\n/)?.[1];
		if (!mac || index(stations, mac) >= 0)
			die('peer_unavailable: Invalid mesh station list');
		push(stations, mac);
		command = 'STA-NEXT ' + mac;
	}
	die('peer_unavailable: Mesh station list exceeds safety limit');
}

export function block_wireless(io, bridge, links) {
	if (links.wireless != 'mm-mesh0' ||
		!match(bridge || '', /^[a-zA-Z0-9_.-]{1,15}$/))
		die('invalid_path: Invalid wireless fail-closed path');
	if (io.master(links.wireless) != bridge) return false;
	io.detach(links.wireless);
	if (io.master(links.wireless) == bridge)
		die('path_block_failed: Wireless data path remains bridged');
	return true;
}

export function wireless_guard(state, identity, snapshot, live, remembered) {
	let frame = active_backhaul_intent(state);
	if (!frame || index(['auto', 'wireless'], frame.intent.backhaul?.mode) < 0 ||
		!match(identity?.id || '', /^[0-9a-f]{32}$/) ||
		identity.role != 'root' && (identity.role != 'ap' || !identity.binding)) return null;
	let mesh_ops = filter(frame.committed ? state.owned || [] :
		state.active.expected_owned || state.active.ops || [],
		(op) => op.config == 'wireless' && op.section == 'mm_mesh0' && op.option == null);
	if (!frame.committed && !length(mesh_ops)) mesh_ops = filter(state.owned || [],
		(op) => op.config == 'wireless' && op.section == 'mm_mesh0' && op.option == null);
	if (length(mesh_ops) != 1 || mesh_ops[0].type != 'wifi-iface' ||
		mesh_ops[0].after?.type != 'wifi-iface' ||
		!equal(snapshot?.wireless?.mm_mesh0, mesh_ops[0].after)) return null;
	let owner = mesh_ops[0].after, mesh = owner.values;
	if (mesh?.ifname != 'mm-mesh0' || mesh.mode != 'mesh' || mesh.network != 'mm_mesh_link' ||
		mesh.mesh_id != frame.intent.backhaul.mesh_id || mesh.device != frame.intent.local?.mesh_radio ||
		mesh.macaddr != frame.intent.local?.mac || !match(mesh.macaddr || '', /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/) ||
		type(live?.ifindex) != 'int' || live.ifindex <= 0 || live.mac != mesh.macaddr ||
		!match(live.phy || '', /^phy[0-9]+$/) || !match(live.boot || '', /^[0-9a-f-]{36}$/)) return null;
	if (remembered && (remembered.boot != live.boot || remembered.id != identity.id ||
		remembered.ifindex != live.ifindex || remembered.mac != live.mac || remembered.phy != live.phy)) return null;
	let bridge = remembered ? remembered.bridge : lan_bridge(state.active?.snapshot || {});
	if (!match(bridge || '', /^[a-zA-Z0-9_.-]{1,15}$/)) return null;
	return { bridge, boot: live.boot, id: identity.id, ifindex: live.ifindex, mac: live.mac, phy: live.phy };
}

export function mesh_peer_present(reply, mac) {
	return type(reply?.result) == 'string' &&
		match(mac || '', /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/) &&
		index(reply.result, mac + '\n') == 0 &&
		index(reply.result, '[AUTH]') > 0 &&
		index(reply.result, '[ASSOC]') > 0;
}

export function control_addresses(id) {
	if (!match(id || '', /^[0-9a-f]{32}$/)) die('invalid_identity: Invalid control-plane identity');
	let third = (int(substr(id, 0, 2), 16) % 100) + 1,
		last = (int(substr(id, 2, 2), 16) % 250) + 1;
	return {
		wired: '169.254.' + third + '.' + last,
		wireless: '169.254.' + (third + 128) + '.' + last
	};
}

export function wired_trial_window(previous, carrier, now, mode, active) {
	let carrier_since = carrier ? previous?.carrier_since ?? now : null,
		trial_after = previous?.trial_after ?? 0;
	return {
		carrier_since,
		trial_after,
		eligible: carrier && active != 'wired' &&
			(mode == 'wired' || mode == 'auto' && now - carrier_since >= 35) &&
			now >= trial_after
	};
}

// A busy peer may briefly preserve an existing data path. It must never renew
// the proof, qualify a standby path, or count towards the wired recovery hold.
export function path_proof(result, previous_at, now, active) {
	let last = result === true ? now : result === null &&
		(type(previous_at) == 'double' || type(previous_at) == 'int') ? previous_at : null;
	if (last != null && (last < 0 || last > now || now - last >= 15)) last = null;
	return { at: last, verified: result === true, usable: result === true ||
		result === null && active === true && last != null };
}

// Runtime state is only evidence for the same physical interfaces, controller,
// configuration and boot. Missing samples or a clock discontinuity reset holds.
export function continuing_observation(previous, binding, now) {
	return previous && equal(previous.binding, binding) &&
		(type(previous.sampled_at) == 'int' || type(previous.sampled_at) == 'double') &&
		now >= previous.sampled_at && now - previous.sampled_at <= 15 ? previous : null;
}

export function select_path(previous, observed, now) {
	let s = { active: 'none', wired_since: null, failed: 0, switched: 0, ...(previous || {}) };
	if (observed.wired === true && observed.wired_fresh !== false) s.wired_since ??= now;
	else s.wired_since = null;
	let active_ok =
		s.active == 'wired' ? observed.wired : s.active == 'wireless' ? observed.wireless : false;
	s.failed = active_ok ? 0 : s.failed + 1;
	let target = s.active;
	if (s.active == 'none' || (!active_ok && (s.failed >= 2 || observed.carrier === false)))
		target = observed.wired ? 'wired' : observed.wireless ? 'wireless' : 'none';
	else if (
		s.active == 'wireless' &&
		observed.wired &&
		s.wired_since != null && now - s.wired_since >= 35 &&
		now - s.switched >= 10
	)
		target = 'wired';
	return { ...s, target };
}

export function reconcile(io, target, bridge, links) {
	if (
		index(['none', 'wired', 'wireless'], target) < 0 ||
		!match(bridge || '', /^[a-zA-Z0-9_.-]{1,15}$/) ||
		!match(links.wired || '', /^[a-zA-Z0-9_.-]{1,15}$/) ||
		links.wireless != 'mm-mesh0' ||
		links.wired == links.wireless
	)
		die('invalid_path: Invalid managed bridge path');
	let expected = target == 'none' ? null : links[target];
	let current = map(['wired', 'wireless'], (p) => ({
		name: links[p],
		master: io.master(links[p])
	}));
	if (
		length(filter(current, (p) => p.master == bridge)) == (expected ? 1 : 0) &&
		(!expected || io.master(expected) == bridge)
	)
		return false;
	// Break before make, and verify reality rather than trusting the previous journal.
	for (let link in current) if (link.master == bridge) io.detach(link.name);
	if (length(filter(values(links), (n) => io.master(n) == bridge)))
		die('path_block_failed: An old data path could not be blocked');
	if (expected) {
		let old = io.master(expected);
		if (old != null && old != bridge) die('ownership_conflict: Uplink belongs to another bridge');
		io.attach(expected, bridge);
		if (
			io.master(expected) != bridge ||
			length(filter(values(links), (n) => io.master(n) == bridge)) != 1
		) {
			for (let name in values(links)) if (io.master(name) == bridge) io.detach(name);
			die('path_enable_failed: Unique data path could not be verified');
		}
	}
	return true;
}

export function bridge_step(io, previous, observed, mode, now, bridge, links) {
	if (index(['wired', 'wireless', 'auto'], mode) < 0)
		die('invalid_mode: Unsupported single-active backhaul mode');
	let wired = io.master(links.wired) == bridge,
		wireless = io.master(links.wireless) == bridge;
	let actual = wired && !wireless ? 'wired' : wireless && !wired ? 'wireless' : 'none';
	let available = {
		carrier: observed.carrier,
		wired: mode != 'wireless' && observed.wired === true,
		wired_fresh: observed.wired_fresh,
		wireless: mode != 'wired' && observed.wireless === true
	};
	let next = select_path({ ...(previous || {}), active: actual }, available, now);
	let target = next.target;
	if (mode == 'wireless') target = available.wireless ? 'wireless' : 'none';
	if (mode == 'wired') target = available.wired ? 'wired' : 'none';
	let changed = reconcile(io, target, bridge, links);
	return {
		boot: observed.boot,
		active: target,
		carrier: observed.carrier,
		wired: available.wired,
		wireless: available.wireless,
		wired_since: next.wired_since,
		failed: next.failed,
		switched: changed ? now : next.switched,
		changed
	};
}
