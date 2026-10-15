// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import { connect } from 'ubus';
import { cursor } from 'uci';
import { mesh_mac } from './extended.uc';
import { lan_bridge } from './topology.uc';
import { active_backhaul_intent, block_wireless, wireless_guard, bridge_step, ensure_mesh_acl, mesh_peer_present, mesh_stations, reconcile, wired_trial_window, path_proof, continuing_observation } from './backhaul.uc';
import { probe_control, probe_management } from './peer_transport.uc';
import * as durable from './durable.uc';
import { reconcile_business } from './business_runtime.uc';
import { physical_root, data_binding } from './authority.uc';

const RUNTIME = '/var/run/mesh-manager-backhaul.json';
const WIRELESS = 'mm-mesh0';
let last_wireless;

function safe_device(name) {
	return type(name) == 'string' && match(name, /^[a-zA-Z0-9_.-]{1,15}$/);
}

function master(name) {
	if (!safe_device(name)) die('invalid_device: Unsafe link name');
	let path = fs.readlink('/sys/class/net/' + name + '/master');
	return path ? fs.basename(path) : null;
}

function set_master(name, bridge, owner) {
	if (!safe_device(name) || !safe_device(owner) || (bridge && bridge != owner))
		die('invalid_device: Unsafe bridge change');
	let args = ['/sbin/ip', 'link', 'set', 'dev', name];
	if (bridge) push(args, 'master', bridge);
	else push(args, 'nomaster');
	if (system(args, 3000) != 0) die('bridge_error: Link master change failed');
}
function business_paths(journal, intent, active) {
	reconcile_business(journal, intent, active, { master,
		detach: (name, bridge) => set_master(name, null, bridge),
		attach: (name, bridge) => set_master(name, bridge, bridge) });
}

function peer_command(bus, name, command, mac) {
	if (name != WIRELESS || index(['MESH_PEER_ADD', 'MESH_PEER_REMOVE'], command) < 0 ||
		!match(mac || '', /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/))
		die('invalid_peer: Unsafe mesh peer operation');
	let result = bus.call('wpa_supplicant.' + name, 'control', {
		command: command + ' ' + mac
	});
	return result?.result == 'OK\n' || result?.result == 'OK';
}

function peer_present(bus, mac) {
	let response = bus.call('wpa_supplicant.' + WIRELESS, 'control', {
		command: 'STA ' + mac
	});
	return mesh_peer_present(response, mac);
}

function peer_acl(identity, intent) {
	if (!fs.access('/sys/class/net/' + WIRELESS)) return;
	let wanted = [];
	if (physical_root(identity,intent) && identity.role=='root') {
		let cluster = durable.load('cluster.json');
		for (let id in keys(cluster?.members || {})) {
			if (!match(id, /^[0-9a-f]{32}$/))
				die('corrupt_state: Invalid member identity');
			if (cluster.members[id].authorized) push(wanted, mesh_mac(id));
		}
	} else if (physical_root(identity,intent)) {
		let roster=durable.load('cluster.json');
		wanted=[mesh_mac(identity.binding.controller_id),...map(filter(keys(roster?.members || {}),
			id=>id!=identity.id && roster.members[id].authorized===true),mesh_mac)];
	} else if (data_binding(identity)) {
		wanted = [mesh_mac(data_binding(identity).controller_id)];
	}
	let bus = connect(null, 1);
	if (!bus) die('peer_unavailable: wpa_supplicant control bus unavailable');
	let error;
	try {
		if (!ensure_mesh_acl(bus, WIRELESS, intent.backhaul.mesh_id))
			die('mesh_acl_unavailable: Cannot enforce manual mesh peering');
		for (let mac in mesh_stations(bus, WIRELESS)) {
			if (index(wanted, mac) >= 0) continue;
			let removed = peer_command(bus, WIRELESS, 'MESH_PEER_REMOVE', mac);
			if (!removed)
				die('peer_revocation_failed: Revoked mesh neighbor remains connected');
		}
		for (let mac in wanted)
			if (!peer_present(bus, mac)) peer_command(bus, WIRELESS, 'MESH_PEER_ADD', mac);
	} catch (e) {
		error = e;
	}
	bus.disconnect();
	if (error) die(error.message || 'peer_unavailable: Mesh peer control failed');
}

function previous(boot) {
	let value;
	try { value = json(fs.readfile(RUNTIME) || 'null'); }
	catch (e) { return null; }
	return value?.boot == boot ? value : null;
}

function write_status(data) {
	// Runtime observations live in tmpfs; durable transactions remain in the local journal.
	fs.writefile(RUNTIME, sprintf('%J', data));
}

function mesh_quality() {
	let bus = connect(null, 1);
	if (!bus) return null;
	let info;
	try { info = bus.call('iwinfo', 'info', { device: WIRELESS }); }
	catch (e) {}
	bus.disconnect();
	if (info?.mode != 'Mesh Point' || type(info.signal) != 'int' ||
		info.signal < -127 || info.signal > 0 ||
		type(info.bitrate) != 'int' || info.bitrate <= 0)
		return null;
	return {
		signal_dbm: info.signal,
		phy_rate_mbps: info.bitrate / 1000.0,
		channel: info.channel
	};
}

function configured_bridge() {
	let c = cursor('/etc/config', '/var/run/mesh-manager-uci', '');
	if (!c.load('network')) die('invalid_topology: LAN configuration is unavailable');
	let network = { lan: { type: 'interface', values: { device: c.get('network', 'lan', 'device') } } };
	c.foreach('network', 'device', (s) => {
		if (s.name == network.lan.values.device)
			network[s['.name']] = { type: 'device', values: { name: s.name, type: s.type } };
	});
	let bridge = lan_bridge({ network });
	if (!bridge || master(bridge) != null || !fs.access('/sys/class/net/' + bridge + '/bridge'))
		die('invalid_topology: Managed LAN bridge is unavailable');
	return bridge;
}

function wireless_proof(identity, journal, remembered) {
	let c = cursor('/etc/config', '/var/run/mesh-manager-uci', '');
	if (!c.load('wireless')) return null;
	let raw = c.get_all('wireless', 'mm_mesh0');
	if (!raw) return null;
	let values = {};
	for (let name in keys(raw)) if (substr(name, 0, 1) != '.') values[name] = raw[name];
	let phy = fs.readlink('/sys/class/net/' + WIRELESS + '/phy80211');
	return wireless_guard(journal, identity, { wireless: { mm_mesh0: { type: raw['.type'], values } } },
		{ boot: durable.boot(), ifindex: int(trim(fs.readfile('/sys/class/net/' + WIRELESS + '/ifindex') || '')),
			mac: trim(fs.readfile('/sys/class/net/' + WIRELESS + '/address') || ''), phy: phy ? fs.basename(phy) : null }, remembered);
}

function current_links(intent, bridge) {
	let wired = intent?.local?.uplink;
	if (!safe_device(wired) || wired == WIRELESS || wired == bridge)
		die('invalid_topology: Managed AP bridge or uplink is unavailable');
	return { wired, wireless: WIRELESS };
}

function observation_binding(identity, journal, links, bridge, boot) {
	let indexes = {};
	for (let name in [bridge, links.wired, links.wireless, 'mm-cw', 'mm-cm'])
		indexes[name] = int(trim(fs.readfile('/sys/class/net/' + name + '/ifindex') || '0'));
	let gateway=data_binding(identity);
	return { boot, indexes, id: identity.id, controller: gateway?.controller_id,
		network: gateway?.network_id, fingerprint: gateway?.ca_fingerprint,
		version: journal.version, transaction: journal.active?.id,
		phase: journal.active?.status, mode: active_backhaul_intent(journal)?.intent.backhaul?.mode };
}

function authenticated_path(binding, device) {
	try { return probe_control(binding, device) === true; }
	catch (e) { return match(e.message || '', /^busy: /) ? null : false; }
}

function authenticated_management(binding) {
	try { return probe_management(binding) === true; }
	catch (e) { return match(e.message || '', /^busy: /) ? null : false; }
}

function wait_forwarding(name, bridge) {
	if (!safe_device(name) || !safe_device(bridge)) return false;
	let path = '/sys/class/net/' + bridge + '/brif/' + name + '/state',
		deadline = durable.now() + 15;
	while (durable.now() < deadline) {
		if (trim(fs.readfile(path) || '') == '3') return true;
		if (system(['/bin/sleep', '1'], 2000) != 0) return false;
	}
	return trim(fs.readfile(path) || '') == '3';
}

export function backhaul_tick() {
	let identity = durable.load('identity.json'), journal = durable.load('state.json'),
		state = active_backhaul_intent(journal);
	if (!identity || !state) { fs.unlink(RUNTIME); return; }
	let mode = state.intent.backhaul?.mode;
	let physical=physical_root(identity,state.intent),gateway=data_binding(identity);
	if (mode == 'wired') {
		if (physical) {write_status({boot:durable.boot(),mode,active:'gateway',wired:true,wireless:false,observed:time()});return;}
		if (!gateway) { fs.unlink(RUNTIME); return; }
		let bridge = configured_bridge(), links = current_links(state.intent, bridge),
			boot = durable.boot(), now = durable.now(), binding = observation_binding(identity, journal, links, bridge, boot),
			prior = continuing_observation(previous(boot), binding, now);
		let carrier = trim(fs.readfile('/sys/class/net/' + links.wired + '/carrier') || '') == '1';
		let attached = master(links.wired) == bridge;
		let verified = carrier && attached ? authenticated_path(gateway,'mm-cw') : false;
		if (carrier && attached && verified !== true) verified = authenticated_management(gateway);
		let proof = path_proof(verified, prior?.wired_verified_at, now, carrier && attached);
		business_paths(journal, state.intent, carrier && attached ? 'wired' : 'none');
		write_status({boot,mode,binding,sampled_at:now,wired_verified_at:proof.at,
			active:carrier && attached ? 'wired' : 'none',carrier,wired:proof.usable,wireless:false,observed:time(),quality:null});
		return;
	}
	if (index(['wireless', 'auto'], mode) < 0)
		die('invalid_mode: Unsupported backhaul mode');
	let bridge = configured_bridge();
	peer_acl(identity, state.intent);
	let proof = wireless_proof(identity, journal);
	if (proof) last_wireless = { ...proof, bridge };
	// A candidate may need its new uplink to reach the controller for confirmation.
	// The local watchdog restores the committed path if confirmation times out;
	// reconcile() still detaches the old bridge path before attaching the new one.
	if (physical) {
		let current = master(WIRELESS);
		if (current && current != bridge)
			die('ownership_conflict: Controller mesh belongs to another bridge');
		if (!current) set_master(WIRELESS, bridge, bridge);
		write_status({boot:durable.boot(),mode,active:'gateway',wired:true,wireless:true,observed:time()});return;
	}
	if (!gateway) return;
	let links = current_links(state.intent, bridge), boot = durable.boot(), now = durable.now();
	let binding = observation_binding(identity, journal, links, bridge, boot),
		prior = continuing_observation(previous(boot), binding, now);
	let carrier = trim(fs.readfile('/sys/class/net/' + links.wired + '/carrier') || '') == '1';
	let active = master(links.wired) == bridge ? 'wired' :
		master(WIRELESS) == bridge ? 'wireless' : 'none';
	let wired_probe = carrier && authenticated_path(gateway, 'mm-cw');
	let management_probe = carrier && active == 'wired' && wired_probe !== true
		? authenticated_management(gateway) : false;
	let wired_result = !carrier ? false : wired_probe === true || management_probe === true ? true :
		management_probe === null || wired_probe === null ? null : false,
		wired_proof = path_proof(wired_result, prior?.wired_verified_at, now, active == 'wired'),
		wired = wired_proof.usable;
	let wireless_result = fs.access('/sys/class/net/' + WIRELESS) ?
		authenticated_path(gateway, 'mm-cm') : false;
	let wireless_proof = path_proof(wireless_result, prior?.wireless_verified_at, now, active == 'wireless'),
		wireless = wireless_proof.usable;
	let io = {
		master,
		detach: (name) => set_master(name, null, bridge),
		attach: (name, target) => set_master(name, target, bridge)
	};
	let trial = wired_trial_window(prior, carrier, now, mode, active),
		trial_result = null, trial_error = null, trial_changed = false;
	if (!wired && trial.eligible) {
		// Tagged control VLANs are not bidirectional on every DSA port. The
		// management probe runs only after the old data path is detached and
		// STP has admitted the new bridge port. A healthy wireless path must
		// not suppress this bounded trial after the stable-carrier hold;
		// otherwise an AP on such a port can never recover wired backhaul.
		try {
			business_paths(journal, state.intent, 'none');
			trial_changed = reconcile(io, 'wired', bridge, links);
			if (!wait_forwarding(links.wired, bridge))
				trial_error = 'bridge_not_forwarding';
			else {
				let verified = authenticated_management(gateway);
				wired = verified === true;
				wired_proof = path_proof(verified, null, now, false);
				if (!wired) trial_error = verified === null
					? 'controller_busy' : 'tls_probe_failed';
			}
		} catch (e) {
			wired = false;
			trial_error = match(e.message || '', /^([a-z_]{1,32}): /)?.[1] ||
				'bridge_error';
		}
		trial_result = wired ? 'verified' : 'failed';
		if (!wired) {
				trial_changed = reconcile(io, wireless ? 'wireless' : 'none', bridge, links) ||
				trial_changed;
			trial.trial_after = now + 60;
		} else trial.trial_after = 0;
	}
	let result = bridge_step(io, prior, { boot, carrier, wired, wireless, wired_fresh: wired_proof.verified },
		mode, now, bridge, links);
	business_paths(journal, state.intent, result.active);
	write_status({ ...result, binding, sampled_at: now,
		wired_verified_at: wired_proof.at, wireless_verified_at: wireless_proof.at, carrier_since: trial.carrier_since,
		trial_after: trial.trial_after, trial_result: trial_result || prior?.trial_result || null,
		trial_error: trial_result ? trial_error : prior?.trial_error || null,
		changed: result.changed || trial_changed,
		switched: trial_changed ? now : result.switched, observed: time(), mode,
		quality: mesh_quality() });
}

export function fail_closed() {
	let identity = durable.load('identity.json');
	let journal = durable.load('state.json'), state = active_backhaul_intent(journal);
	if (index(['wireless', 'auto'], state?.intent?.backhaul?.mode) < 0) return;
	if (identity?.role != 'root' && (identity?.role != 'ap' || !identity.binding)) return;
	if (!fs.access('/sys/class/net/' + WIRELESS)) return;
	// Recovery must not require the damaged LAN topology to pass normal admission.
	let proof = wireless_proof(identity, journal, last_wireless);
	if (!proof) return;
	let bridge = proof.bridge;
	// Wireless uncertainty must not sever an independently working wired uplink.
	block_wireless({ master, detach: (name) => set_master(name, null, bridge) },
		bridge, { wireless: WIRELESS });
}
