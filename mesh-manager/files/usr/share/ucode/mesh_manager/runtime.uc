// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import { cursor } from 'uci';
import { connect } from 'ubus';
import * as crypto from 'mesh_crypto';
import { write_cas } from './durable.uc';
import { run } from 'mesh_process';
import { uci_sections } from 'mesh_data';
import { json_reader } from './read_cache.uc';
import { engine, owned_matches } from './transaction.uc';
import { clone, equal, canonical, static_ipv4_matches } from './model.uc';
import { value } from './compiler.uc';
import { network_inventory } from './network_extensions.uc';
import { request } from './bus.uc';
import { mesh_acl_enabled } from './backhaul.uc';
import { restore_checks as restoration_checks } from './restore.uc';
import { execute as reload_services } from './reload.uc';
import { acquire } from './locking.uc';
import { steering_capabilities, steering_observation, steering_verify } from './roaming_runtime.uc';
import { steering_service_action } from './roaming.uc';
import { lan_service_health, lan_service_diagnostics } from './service_health.uc';
import { service_desired } from './service_runtime.uc';
import { observed_background } from './service_policy.uc';
import { note_state } from './event_log.uc';
import { software_status } from './software_status.uc';
import { cached_wireless_features } from './capability_features.uc';
import { wireless_link_compatibility } from './wireless_compatibility.uc';
import { handoff_check, handoff_stamp } from './first_handoff.uc';
import { radio_modes } from './radio_modes.uc';
import { business_dhcp_ready } from './business_health.uc';
import { extension_bridge, extension_device } from './network_extensions.uc';

const CONFIGS = ['network', 'wireless', 'dhcp', 'firewall', 'usteer'];
const STATE = '/etc/mesh-manager/state.json';
const LOCK = '/var/run/mesh-manager.lock';
const HEARTBEAT = '/var/run/mesh-manager.heartbeat';
const BACKHAUL_STATUS = '/var/run/mesh-manager-backhaul.json';
const SAVEDIR = '/var/run/mesh-manager-uci';
const APPROVAL_KEY = '/var/run/mesh-manager-approval.key';
const read_json = json_reader();

export function status_view(view) {
	if (view == null || view == '') return 'full';
	if (type(view) != 'string' || index(['overview', 'nodes', 'wireless', 'backhaul',
		'clients', 'clients_brief', 'history', 'diagnostics', 'agent', 'full'], view) < 0)
		die('invalid_view: Unknown Mesh Manager status view');
	return view;
}

function approval_key(create) {
	let st = fs.lstat(APPROVAL_KEY);
	if (!st) {
		if (create === false) die('preview_changed: Approval key disappeared during preview compilation');
		let f = fs.open('/dev/urandom', 'r'), random = f?.read(32);
		f?.close();
		if (length(random) != 32) die('entropy_error: Approval entropy unavailable');
		f = fs.open(APPROVAL_KEY, 'w', 0600);
		let written = f?.write(hexenc(random));
		f?.close();
		if (written != 64) die('storage_error: Cannot create approval key');
		st = fs.lstat(APPROVAL_KEY);
	}
	if (st?.type != 'file' || st.uid != 0 || st.mode & 0077 || st.size != 64)
		die('storage_error: Unsafe approval key');
	let key = fs.readfile(APPROVAL_KEY);
	if (!match(key || '', /^[0-9a-f]{64}$/)) die('storage_error: Invalid approval key');
	return key;
}
function keyed_seal(key, payload) {
	let token = crypto.hmac(key, sprintf('%J', canonical(payload)));
	if (!token) die('storage_error: Approval binding failed');
	return token;
}
function seal(payload) { return keyed_seal(approval_key(), payload); }

function now() {
	let uptime = fs.readfile('/proc/uptime');
	if (!uptime || !match(uptime, /^[0-9]+\.[0-9]+ /))
		die('clock_error: Monotonic uptime unavailable');
	return +split(uptime, ' ')[0];
}
function boot() {
	let id = trim(fs.readfile('/proc/sys/kernel/random/boot_id') || '');
	if (!match(id, /^[0-9a-f-]{36}$/)) die('clock_error: Boot identity unavailable');
	return id;
}
export function recovery_available() {
	let observed;
	try { observed=json(fs.readfile(HEARTBEAT) || 'null'); } catch(e) { observed=null; }
	let clock=now();
	return observed?.boot==boot() &&
		(type(observed?.uptime)=='int' || type(observed?.uptime)=='double') &&
		clock>=observed.uptime && clock-observed.uptime<10;
}
function uci() {
	let directory = fs.lstat(SAVEDIR);
	if (!directory) {
		fs.mkdir(SAVEDIR, 0700);
		directory = fs.lstat(SAVEDIR);
	}
	if (!directory || directory.type != 'directory' || directory.uid != 0 || directory.mode & 0077)
		die('storage_error: Unsafe private UCI directory');
	return cursor('/etc/config', SAVEDIR, '');
}
export function snapshot() {
	let c = uci(),
		result = {};
	for (let config in CONFIGS) {
		if (!c.load(config)) {
			if (config == 'usteer') continue;
			die('configuration_error: Cannot load ' + config);
		}
		result[config] = uci_sections(c.get_all(config));
	}
	return result;
}
function bus(timeout) {
	return connect(null, timeout ?? 1);
}
function call(connection, object, method, args) {
	try {
		return connection?.call(object, method, args || {});
	} catch (e) {
		return null;
	}
}
export function guest_network_snapshot() {
	let current=snapshot(),b=bus();
	current.business_inventory=network_inventory(call(b,'network.interface','dump'));
	b?.disconnect();return current;
}
function settings() {
	let c = uci(),
		result = {};
	c.load('mesh-manager');
	for (let field in ['confirmation_timeout', 'candidate_timeout']) {
		let n = int(c.get('mesh-manager', 'main', field));
		result[field] = n >= 60 && n <= 600 ? n : field == 'confirmation_timeout' ? 120 : 300;
	}
	return result;
}
function settings_source() {
	let path = '/etc/config/mesh-manager', source = fs.readfile(path);
	if (source == null && fs.lstat(path) != null)
		die('configuration_error: Cannot read Mesh Manager preview settings');
	return source;
}
function wireless_features(cached) {
	let hostapd = fs.access('/usr/sbin/hostapd'), mesh_control = fs.access('/usr/share/hostap/wpa_supplicant.uc');
	if (cached === true) {
		let observed = cached_wireless_features();
		return { hostapd, mesh_control, sae:observed.sae, ft:observed.ft, mesh:observed.mesh,
			probe_errors:observed.wireless_probe_errors, state:observed.wireless_features_state };
	}
	// Configuration preflight always probes the installed binaries; an advisory status
	// cache never authorizes a write or supplies an approval.
	let wpa = fs.access('/usr/sbin/wpa_supplicant'),
		sae = hostapd ? run(['/usr/sbin/hostapd', '-vsae'], '', 3000)?.code : 1,
		ft = hostapd ? run(['/usr/sbin/hostapd', '-v11r'], '', 3000)?.code : 1,
		mesh = wpa ? run(['/usr/sbin/wpa_supplicant', '-vmesh'], '', 3000)?.code : 1;
	let codes = { sae, ft, mesh }, probe_errors = filter(keys(codes), name => index([0, 1], codes[name]) < 0);
	let control_status=mesh_control && mesh===0 ? wireless_link_compatibility(run) : null;
	if (control_status=='unavailable') push(probe_errors,'link_flags');
	return { hostapd, mesh_control, sae:hostapd && sae==0, ft:hostapd && ft==0, mesh:wpa && mesh==0,
		control_status, probe_errors, state:length(probe_errors)?'unavailable':'ready' };
}
export function capabilities(snapshot, cached, intent) {
	let identity_path = '/etc/mesh-manager/identity.json', identity_stat = fs.lstat(identity_path), controller_identity = null;
	if (identity_stat) {
		if (identity_stat.type != 'file' || identity_stat.uid != 0 || identity_stat.mode & 0077 || identity_stat.size > 1024 * 1024)
			die('identity_error: Cannot read trusted controller identity');
		let identity;
		try { identity = json(fs.readfile(identity_path)); }
		catch (e) { die('identity_error: Cannot read trusted controller identity'); }
		if (type(identity) != 'object' || index(['unbound', 'root', 'ap'], identity.role) < 0)
			die('identity_error: Cannot read trusted controller identity');
		controller_identity = { role: identity.role, address: identity.role == 'root' ? identity.address : null };
	}
	let pending = false;
	for (let config in CONFIGS) {
		if (length(fs.readfile('/tmp/.uci/' + config) || '') || fs.stat('/var/run/uci/' + config))
			pending = true;
	}
	let features = wireless_features(cached),
		hostapd = features.hostapd, sae = features.sae, mesh = features.mesh,
		mesh_control = features.mesh_control;
	let b = bus();
	// wpa_supplicant's control API is verified again on the live mesh interface.
	let mesh_acl = mesh && mesh_control,
		wireless_ready = mesh && sae && mesh_control && mesh_acl;
	let result = {
		controller_identity,
		dnsmasq: fs.access('/etc/init.d/dnsmasq'),
		firewall: fs.access('/sbin/fw4'),
		hostapd,
		sae,
		ft: features.ft,
		wireless_probe_errors: features.probe_errors,
		wireless_features_state: features.state,
		mesh,
		mesh_control,
		wireless_control_status: features.control_status ?? null,
		mesh_acl,
		usteer: fs.access('/sbin/usteerd'),
		dawn: fs.access('/etc/init.d/dawn') && system(['/etc/init.d/dawn', 'running'], 1000) == 0,
		pending_changes: pending,
		daemon: false,
		bus: b != null,
		radios: radio_modes(map(
			filter(keys(snapshot.wireless), (k) => snapshot.wireless[k].type == 'wifi-device'),
			(k) => ({
				name: k,
				band: snapshot.wireless[k].values.band || null,
				channel: snapshot.wireless[k].values.channel || 'auto',
				country: snapshot.wireless[k].values.country || null
			})
		), cached, name => call(b, 'iwinfo', 'info', { device: name }),
			name => call(b, 'iwinfo', 'freqlist', { device: name })),
		backhaul_modes: wireless_ready ? ['wired', 'wireless', 'auto'] : ['wired'],
		wireless_backhaul: sae==null || mesh==null ? 'unconfirmed' : wireless_ready ? 'preflight_required' : 'dependency_missing',
		roaming: 'configuration_supported',
		address_conflict: 'not_checked'
	};
	result.daemon = recovery_available();
	result.daemon_on_demand=fs.access('/etc/init.d/mesh-manager');
	let background=service_desired();
	let services=call(b,'service','list',{name:'mesh-manager'}),
		observed=observed_background(background,type(services)=='object' ? services['mesh-manager']?.instances || {} : null);
	result.background=observed.mode;
	result.background_instances=background.instances;
	result.background_actual_instances=observed.instances;
	if (!cached && result.usteer) result.usteer_support = steering_capabilities(b);
	if (!cached && length(filter(intent?.networks || [],n=>n.enabled)))
		result.business_inventory=network_inventory(call(b,'network.interface','dump'));
	b?.disconnect();
	return result;
}
function load(cached) {
	let dir = fs.lstat('/etc/mesh-manager');
	if (dir && (dir.type != 'directory' || dir.uid != 0 || dir.mode & 0077))
		die('storage_error: Unsafe persistent state directory');
	let st = fs.lstat(STATE);
	if (!st) { if(cached===true)read_json(null);return null; }
	if (st.type != 'file' || st.uid != 0 || st.mode & 0077 || st.size > 1024 * 1024)
		die('storage_error: Unsafe persistent state file');
	let content = fs.readfile(STATE);
	if (!content) die('corrupt_state: Cannot read persistent journal');
	try {
		let result = cached===true ? read_json(content) : json(content);
		if (type(result) != 'object') die('Invalid persistent object');
		return result;
	} catch (e) {
		die('corrupt_state: Persistent journal is invalid');
	}
}
function save(state) {
	let content = sprintf('%J', state);
	if (length(content) > 1024 * 1024) die('storage_error: Journal size limit exceeded');
	let result = run(['/usr/libexec/mesh-manager-store'], content, 5000);
	if (result?.code != 0) die('storage_error: Durable state write failed');
	note_state('state.json',state);
}
function write(ops) {
	for (let config in CONFIGS) {
		let group = filter(ops, (op) => op.config == config);
		if (!length(group)) continue;
		let current = snapshot(),
			c = uci();
		c.load(config);
		for (let op in group) {
			if (
				!equal(value(current, op) ?? null, op.before) ||
				(op.option != null && current[config]?.[op.section]?.type != op.type)
			)
				die('ownership_conflict: Configuration changed while applying');
			if (equal(op.before, op.after)) continue;
			if (op.option == null) {
				if (op.after == null) {
					if (!c.delete(config, op.section)) die('write_error: Cannot delete managed section');
				} else {
					if (c.get_all(config, op.section) && !c.delete(config, op.section))
						die('write_error: Cannot replace managed section');
					if (!c.set(config, op.section, op.after.type))
						die('write_error: Cannot create managed section');
					for (let option in keys(op.after.values))
						if (!c.set(config, op.section, option, op.after.values[option]))
							die('write_error: Cannot set managed section value');
				}
			} else if (op.after == null) {
				if (
					c.get(config, op.section, op.option) != null &&
					!c.delete(config, op.section, op.option)
				)
					die('write_error: Cannot delete managed option');
			} else if (!c.set(config, op.section, op.option, op.after))
				die('write_error: Cannot set managed option');
		}
		if (!c.commit(config)) die('write_error: UCI commit failed');
	}
	if (length(ops) && system(['/bin/sync'], 10000) != 0)
		die('write_error: Configuration durability flush failed');
}
function steering_network_ready(timeout) {
	let deadline=now()+timeout/1000,current=snapshot(),radios={},networks=[],steady=null,b=bus(1),complete=false;
	for(let name,section in current.wireless || {})
		if(index(name,'mm_')==0 && section.type=='wifi-iface' && section.values.disabled!='1')radios[section.values.device]=true;
	for(let section in values(current.usteer || {}))if(section.type=='usteer') {
		if(section.values.enabled=='0'){b?.disconnect();return true;}
		networks=section.values.network || [];
		if(type(networks)=='string')networks=filter(split(networks,' '),n=>length(n));
	}
	try {
		while(now()<deadline) {
			let ready=false;
			try {
				let wireless=request(b,'network.wireless','status',{});
				ready=!length(filter(keys(radios),name=>wireless[name]?.up!==true || wireless[name]?.pending===true));
				for(let network in networks) {
					if(now()>=deadline){ready=false;break;}
					let status=request(b,'network.interface.'+network,'status',{});
					if(status.up!==true || !status.l3_device)ready=false;
				}
			} catch(e) {ready=false;}
			if(ready){if(steady!=null && now()-steady>=0.5){complete=true;break;}steady ??= now();}
			else steady=null;
			if(now()<deadline)sleep(200);
		}
	} catch(e) {b?.disconnect();die(e.message);}
	b?.disconnect();return complete;
}
function reload(ops, confirmation_deadline) {
	reload_services(ops, {
		now,
		network: (timeout) => {
			let b = bus(timeout);
			try { request(b, 'network', 'reload', {}); }
			catch (e) { b?.disconnect(); die(e.message); }
			b?.disconnect();
		},
		available: (name) => fs.access('/etc/init.d/' + name),
		network_ready: steering_network_ready,
		service: (name, timeout, action) => system(['/etc/init.d/' + name,
			name == 'usteer' && action != 'stop' ? steering_service_action(snapshot()) : action], timeout) == 0
	}, confirmation_deadline);
}
function health(active) {
	let checks = [],
		b = bus(),
		current = snapshot();
	checks = [...checks, ...steering_verify(current,active,b)];
	checks = [...checks, ...lan_service_health(current, name => call(b,'service','list',{name}))];
	let lan = call(b, 'network.interface.lan', 'status');
	push(checks, {
		name: 'management_interface',
		ok: lan?.up === true && length(lan['ipv4-address'] || []) > 0
	});
	push(checks, {
		name: 'management_protocol',
		ok: lan?.proto == current.network.lan?.values?.proto
	});
	if (current.network.lan?.values?.proto == 'static')
		push(checks, {
			name: 'management_address',
			ok: static_ipv4_matches(current.network.lan.values, lan?.['ipv4-address'])
		});
	push(checks, {
		name: 'expected_configuration',
		ok: !length(filter(active.ops, (op) =>
			!equal(value(current, op) ?? null, op.after) ||
			(op.option != null && current[op.config]?.[op.section]?.type != op.type))) &&
			!length(filter(active.expected_owned || [], (op) => !owned_matches(current, op)))
	});
	if (active.kind != 'release' && active.intent?.gateway == 'router')
		push(checks, {
			name: 'wan_interface',
			ok: call(b, 'network.interface.wan', 'status')?.up === true
		});
	if (active.kind != 'release' && active.intent?.wifi?.enabled) {
		let wireless = call(b, 'network.wireless', 'status') || {};
		for (let radio in active.intent.wifi.radios) {
			let interfaces = wireless[radio]?.interfaces || [];
			let ap = filter(interfaces, (iface) => iface.section == 'mm_ap_' + radio)[0];
			push(checks, {
				name: 'ap_' + radio,
				ok:
					wireless[radio]?.up === true &&
					call(b, 'hostapd.' + (ap?.ifname || ''), 'get_status')?.status == 'ENABLED'
			});
		}
	}
	if (active.kind != 'release' && active.intent?.schema == 2) {
		let wireless = call(b, 'network.wireless', 'status') || {},
			radios = active.intent.wifi.radios;
		for (let network in active.intent.networks || []) {
			if (!network.enabled) continue;
			let name = 'mm_' + network.id, status = call(b, 'network.interface.' + name, 'status'),
				bridge = extension_bridge(network.id);
			push(checks, { name: network.id + '_interface', ok: status?.up === true && status.device == bridge &&
				fs.access('/sys/class/net/' + bridge + '/bridge') && (active.intent.gateway != 'router' ||
				static_ipv4_matches(current.network[name]?.values || {}, status['ipv4-address'])) });
			if (active.intent.gateway=='router') {
                let instances=call(b,'service','list',{name:'dnsmasq'})?.dnsmasq?.instances;
                push(checks,{name:network.id+'_dhcp',ok:business_dhcp_ready(network.id,network.subnet,current,instances,path=>{
                    let before=fs.lstat(path);if(before?.type!='file' || before.uid!=0 || before.size>131072)return null;
                    let raw=fs.readfile(path),after=fs.lstat(path);
                    return before.inode==after?.inode && before.size==after.size ? raw : null;
                })});
            }
			for (let radio in radios) {
				let ap = filter(wireless[radio]?.interfaces || [], iface => iface.section == name + '_' + radio)[0];
				push(checks, { name: network.id + '_ap_' + radio, ok: wireless[radio]?.up === true &&
					call(b, 'hostapd.' + (ap?.ifname || ''), 'get_status')?.status == 'ENABLED' });
			}
			if (!active.intent.controller && active.intent.data_root !== true) {
				let attached = [];
				for (let path in ['w', 'm']) {
					let master = fs.readlink('/sys/class/net/' + extension_device(network.id, path) + '/master');
					if (master && fs.basename(master) == bridge) push(attached, path);
				}
				push(checks, { name: network.id + '_single_uplink', ok: length(attached) == 1 });
			}
		}

	}
	if (active.kind != 'release' && active.intent?.schema == 2 && active.intent.backhaul?.mode != 'wired') {
		let wireless = call(b, 'network.wireless', 'status') || {};
		let radio = active.intent.local.mesh_radio;
		let mesh = filter(wireless[radio]?.interfaces || [], (iface) => iface.section == 'mm_mesh0')[0];
		let ifname = mesh?.ifname;
		let response = ifname ? call(b, 'wpa_supplicant.' + ifname, 'control', { command: 'STATUS' }) : null;
		let peer_acl = false;
		try {
			peer_acl = mesh_acl_enabled(b, ifname, active.intent.backhaul.mesh_id);
		} catch (e) {}
		push(checks, {
			name: 'backhaul_mesh',
			ok: wireless[radio]?.up === true && ifname == 'mm-mesh0' &&
				fs.access('/sys/class/net/' + ifname) &&
				type(response?.result) == 'string' && index(response.result, 'FAIL') < 0
		});
		push(checks, { name: 'backhaul_peer_acl', ok: peer_acl });
	}
	b?.disconnect();
	return { ok: !length(filter(checks, (c) => !c.ok)), checks, data_path_verified: false };
}
function clients_from_objects(connection, objects) {
	let clients = [], client_errors = [];
	if (type(objects) != 'array') {
		push(client_errors, 'hostapd_enumeration_unavailable');
		objects = [];
	}
	for (let object in objects) {
		if (type(object) != 'string') {
			if (index(client_errors, 'hostapd_enumeration_unavailable') < 0)
				push(client_errors, 'hostapd_enumeration_unavailable');
			continue;
		}
		if (index(object, 'hostapd.') != 0) continue;
		let result = call(connection, object, 'get_clients');
		if (type(result?.clients) != 'object') {
			push(client_errors, object);
			continue;
		}
		for (let mac in keys(result.clients)) {
			let c = result.clients[mac];
			if (type(c) != 'object') {
				if (index(client_errors, object) < 0) push(client_errors, object);
				continue;
			}
			push(clients, {
				address: mac,
				interface: substr(object, 8),
				authorized: c.authorized === true,
				signal: c.signal ?? null
			});
		}
	}
	return { clients, client_errors, complete: !length(client_errors) };
}
export function client_observation(connection) {
	let objects;
	try { objects = connection?.list(); }
	catch (e) { objects = null; }
	return clients_from_objects(connection, objects);
}
export function managed_client_observation(connection, wireless, intent) {
	if (!intent?.wifi) return {clients:[],client_errors:['mesh_not_enabled'],complete:false};
	if (!intent.wifi.enabled) return {clients:[],client_errors:[],complete:true};
	let objects=[],errors=[];
	for (let radio in intent.wifi.radios || []) {
		let entry=wireless?.[radio],interfaces=entry?.interfaces;
		let ap=type(interfaces)=='array' ? filter(interfaces,row=>row.section=='mm_ap_'+radio) : [];
		if (entry?.up!==true || length(ap)!=1 || !match(ap[0]?.ifname || '',/^[a-zA-Z0-9_.-]{1,15}$/))
			push(errors,'managed_ap_unavailable');
		else push(objects,'hostapd.'+ap[0].ifname);
	}
	if (!length(objects)) push(errors,'managed_ap_unavailable');
	let result=clients_from_objects(connection,objects);
	result.client_errors=[...errors,...result.client_errors];result.complete=!length(result.client_errors);
	return result;
}
export function observe_clients(intent) {
	let connection = bus();
	try {
		let result = managed_client_observation(connection, call(connection, 'network.wireless', 'status'), intent);
		connection?.disconnect();
		return result;
	} catch (e) {
		connection?.disconnect();
		die(e.message || '' + e);
	}
}
function observe(snapshot, view, intent) {
	let full = !view || view == 'full',
		clients_needed = full || view == 'clients' || view == 'agent',
		dfs_needed = full || view == 'diagnostics';
	let b = bus();
	let board = full || index(['overview', 'nodes', 'clients', 'wireless', 'backhaul', 'agent', 'diagnostics'], view) >= 0
		? call(b, 'system', 'board') : null;
	let lan = full || index(['overview', 'nodes', 'agent'], view) >= 0
		? call(b, 'network.interface.lan', 'status') : null;
	let wireless = clients_needed ? call(b, 'network.wireless', 'status') : null;
	let dfs = [];
	let objects;
	try { objects = clients_needed && view != 'agent' || dfs_needed ? b?.list() : []; }
	catch (e) { objects = null; }
	let sampled_clients = clients_needed ? view == 'agent' ? managed_client_observation(b, wireless, intent) : clients_from_objects(b, objects) : null;
	for (let object in type(objects) == 'array' && dfs_needed ? objects : []) {
		if (type(object) != 'string' || index(object, 'hostapd.') != 0) continue;
		let ap_status = dfs_needed ? call(b, object, 'get_status') : null;
		if (type(ap_status?.phy) == 'string' &&
			!length(filter(dfs, (item) => item.radio == ap_status.phy)))
			push(dfs, {
				radio: ap_status.phy,
				channel: type(ap_status.channel) == 'int' ? ap_status.channel : null,
				cac_active: type(ap_status.dfs?.cac_active) == 'bool' ?
					ap_status.dfs.cac_active : null,
				cac_seconds_left: type(ap_status.dfs?.cac_seconds_left) == 'int' ?
					ap_status.dfs.cac_seconds_left : null
			});
	}
	let bridge = filter(
		keys(snapshot.network),
		(k) =>
			snapshot.network[k].type == 'device' &&
			snapshot.network[k].values.name == snapshot.network.lan?.values?.device
	)[0];
	let ports = snapshot.network[bridge]?.values?.ports || [];
	let links = map(type(ports) == 'array' ? ports : [ports], (name) => ({
		name,
		carrier: match(name, /^[a-zA-Z0-9_.-]{1,32}$/)
			? trim(fs.readfile('/sys/class/net/' + name + '/carrier') || 'unknown')
			: 'unknown'
	}));
	let backhaul;
	try {
		let observed = json(fs.readfile(BACKHAUL_STATUS) || 'null');
		if (observed?.boot == boot() && type(observed.observed) == 'int' &&
			time() - observed.observed >= 0 && time() - observed.observed < 15 &&
			index(['wired', 'wireless', 'none'], observed.active) >= 0) {
			backhaul = {
				active: observed.active,
				carrier: observed.carrier === true,
				wired: observed.wired === true,
				wireless: observed.wireless === true,
				mode: observed.mode,
				trial_result: observed.trial_result,
				trial_error: observed.trial_error,
				quality: observed.quality || null
			};
		}
	} catch (e) {}
	let result = {
		...(full || view == 'agent' || view == 'diagnostics'
			? { software: software_status({
				...(type(board?.release) == 'object' ? board.release : {}),
				kernel: board?.kernel
			}) } : {}),
		board: board
			? { model: board.model, hostname: board.hostname, release: board.release?.version }
			: null,
		management: lan
			? { up: lan.up, addresses: lan['ipv4-address'] || [], device: lan.l3_device }
			: null,
		wan_device: snapshot.network?.wan?.values?.device || null,
		backhaul: backhaul || null,
		bus_available: b != null
	};
	if (full) result.links = links;
	if (dfs_needed) result.dfs = dfs;
	if (view == 'diagnostics') result.lan_services = lan_service_diagnostics(snapshot,
		name => call(b, 'service', 'list', {name}), time());
	if (clients_needed) {
		result.wireless_available = wireless != null;
		result.clients = sampled_clients.clients;
		result.client_errors = sampled_clients.client_errors;
		result.clients_complete = sampled_clients.complete;
	}
	b?.disconnect();
	return result;
}
// Read actual management and cached path data without UCI snapshots,
// capability detection, client sampling or network probes.
export function topology_observation() {
	return observe({network:{}}, 'overview', null);
}
function id() {
	let f = fs.open('/dev/urandom', 'r'),
		random = f?.read(16);
	f?.close();
	if (length(random) != 16) die('entropy_error: Cannot obtain transaction entropy');
	return hexenc(random);
}

function with_lock(callback, attempts, shared) {
	let lock = fs.open(LOCK, 'a', 0600);
	if (!lock) die('storage_error: Cannot open Mesh Manager lock file');
	if (!acquire(lock, attempts, shared)) {
		lock.close();
		die('busy: Mesh Manager is handling another request');
	}
	try {
		let result = callback();
		lock.close();
		return result;
	} catch (e) {
		lock.close();
		die(e.message || '' + e);
	}
}
export function read_locked(callback, attempts) { return with_lock(callback, attempts, true); }
// Only configuration commands ask for these live Root AP identities. An SSID
// alone cannot select a recovery peer when another router uses the same name.
export function root_bootstrap_wifi() {
	return read_locked(() => {
		let config=snapshot().wireless, b=bus(), wireless=call(b,'network.wireless','status',{}), points=[];
		b?.disconnect();
		for(let radio in values(wireless || {})) for(let iface in radio.interfaces || []) {
			let ap=config[iface.section]?.values;
			if(!match(iface.section || '',/^mm_ap_/) || ap?.mode!='ap' || ap.disabled=='1' ||
				!match(iface.ifname || '',/^[a-zA-Z0-9_.-]{1,32}$/))continue;
			let bssid=trim(fs.readfile('/sys/class/net/'+iface.ifname+'/address') || '');
			if(type(ap.ssid)=='string' && length(ap.ssid)>=1 && length(ap.ssid)<=32 &&
				match(bssid,/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/))push(points,{ssid:ap.ssid,bssid});
		}
		return slice(sort(points,(a,b)=>a.bssid<b.bssid ? -1 : a.bssid>b.bssid ? 1 : 0),0,8);
	});
}
export function frozen_recovery_pending(io) {
	let journal = io.read_locked(io.load, 5);
	// Only a scheduling hint. The exclusive tick rereads and validates all inputs.
	return engine({ load: () => journal }).recovery_pending();
}
export function recovery_pending() {
	return frozen_recovery_pending({ read_locked, load: () => load(true) });
}
export function history_records() {
	return read_locked(() => engine({ load: () => load(true) }).history(), 5);
}
// Private journal recovery predicate; no rpcd method or raw checkpoint export.
export function restoration_committed(id, request) {
	return read_locked(() => engine({load:()=>load(true),snapshot,
		restore_checks:(s,ops,intent)=>restoration_checks(s,ops,intent,
			port=>match(port,/^[a-zA-Z0-9_-]{1,15}$/) ?
				trim(fs.readfile('/sys/class/net/'+port+'/carrier') || 'unknown') : 'unknown')
	}).restoration_committed(id,request),5);
}
// An authenticated retirement checkpoint retains the old raw journal. Verify
// its restoration against the current configuration without restoring old data.
export function departure_locked(callback) {
	return with_lock(() => callback({snapshot,
		verify:(raw,id,request)=>engine({load:()=>json(raw),snapshot,
			restore_checks:(s,ops,intent)=>restoration_checks(s,ops,intent,port=>
				match(port,/^[a-zA-Z0-9_-]{1,15}$/) ? trim(fs.readfile('/sys/class/net/'+port+'/carrier') || 'unknown') : 'unknown')
		}).restoration_committed(id,request)
	}),5);
}
export function locked(callback, attempts, private_save) {
	return with_lock(() => callback(
			engine({
				load,
				save: private_save || save,
				snapshot,
				capabilities,
				settings,
				write,
				reload,
				health,
				observe,
				restore_checks: (s, ops, intent) => restoration_checks(s, ops, intent,
					(port) => match(port, /^[a-zA-Z0-9_-]{1,15}$/)
						? trim(fs.readfile('/sys/class/net/' + port + '/carrier') || 'unknown') : 'unknown'),
				id,
				seal,
				boot,
				now,
				wall: () => time()
			})
		), attempts);
}

export function authorize_restoration(id, request) {
	return locked(service => service.authorize_restoration(id,request),5);
}

export function clear_history(args) {
	return locked(service => service.clear_history(args), 5);
}

// Internal adapter only. No ubus method accepts this private signed context or
// the capture callback. The lineage is published with the original staged save.
export function first_handoff_locked(callback) {
	return with_lock(callback, 1);
}
export function first_handoff_stage(intent, request_id, takeover, approval, frame, proof, capture) {
	if (type(capture) != 'function' || type(proof) != 'object')
		die('handoff_conflict: First configuration staging requires its private signed context');
	function unchanged() {
		let current = capture();
		if (!handoff_check(frame, current.scope, current.journal, current.snapshot,
			current.boot, current.now, current.transport))
			die('handoff_conflict: Original first configuration snapshot changed');
		return current;
	}
	return locked(service => {
		unchanged();
		return service.stage(intent, request_id, takeover, approval);
	}, 1, state => {
		let current = unchanged();
		if (current.now + 5000 >= frame.deadline)
			die('timeout: First configuration staging has no remaining durable write budget');
		let stamped = handoff_stamp(current.scope, current.journal, sprintf('%J', state), current.snapshot,
			proof.request, proof.reply, intent, time());
		write_cas('state.json', current.journal, stamped, min(5000, frame.deadline - current.now));
		note_state('state.json', json(stamped));
		let actual = capture();
		if (type(actual.now) != 'int' || actual.journal !== stamped || !equal(actual.scope, frame.scope) ||
			actual.snapshot !== frame.snapshot || actual.boot !== frame.boot ||
			!equal(actual.transport, frame.transport) || actual.now < frame.started || actual.now >= frame.deadline)
			die('handoff_conflict: First staged lineage publication was replaced or arrived too late');
	});
}

export function publish_observation(target, value) {
	if (type(target)!='string' || index(target,'\0')>=0)die('invalid_file: Invalid observation path');
	if (target!=HEARTBEAT && target!='/var/run/mesh-manager-agent.json' &&
		!match(target || '',/^\/var\/run\/mesh-manager-seen-[0-9a-f]{32}$/))
		die('invalid_file: Unknown volatile observation');
	let previous=fs.lstat(target),content=sprintf('%J',value);
	if (length(content)>1024 || previous && (previous.type!='file' || previous.uid!=0 || previous.mode&0022))
		die('storage_error: Unsafe volatile observation');
	let directory = fs.mkdtemp('/var/run/mesh-manager-heartbeat.XXXXXX');
	if (!directory) die('storage_error: Cannot create heartbeat directory');
	let path = directory + '/value', file;
	try {
		file = fs.open(path, 'w', 0600);
		let complete = file && file.write(content) == length(content) && file.flush();
		file?.close(); file = null;
		if (!complete || !fs.rename(path, target))
			die('storage_error: Cannot publish recovery heartbeat');
		fs.rmdir(directory);
	} catch (e) {
		file?.close(); fs.unlink(path); fs.rmdir(directory);
		die(e.message || '' + e);
	}
}
export function heartbeat() {
	publish_observation(HEARTBEAT,{boot:boot(),uptime:now()});
}
export function frozen_repair_preview(io, intent, context) {
	let frame = io.locked(() => ({ journal: io.load(), snapshot: io.snapshot(),
		boot: io.boot(), settings_source: io.settings_source(), settings: clone(io.settings()),
		key: io.approval_key(), now: io.now() }), 5);
	// Compile only frozen private inputs; stage still checks the actual raw approval under its lock.
	let service = engine({ load: () => clone(frame.journal), snapshot: () => clone(frame.snapshot),
		boot: () => frame.boot, settings: () => frame.settings, now: () => frame.now,
		capabilities: io.capabilities, seal: (payload) => keyed_seal(frame.key, payload)
	});
	let plan = context ? service.local_overrides_preview(intent, context) : service.repair_preview(intent);
	let actual = io.locked(() => ({ journal: io.load(), snapshot: io.snapshot(),
		boot: io.boot(), settings_source: io.settings_source(), settings: io.settings(),
		key: io.approval_key(false), now: io.now() }), 5);
	// This read-only fence linearizes at capture; stage independently checks the live raw approval.
	if (!equal(actual.journal, frame.journal) || !equal(actual.snapshot, frame.snapshot) ||
		actual.boot != frame.boot || !equal(actual.settings_source, frame.settings_source) ||
		!equal(actual.settings, frame.settings) || actual.key != frame.key)
		die('preview_changed: Repair preview inputs changed during compilation');
	let clock = io.now();
	if (actual.now < frame.now || clock < actual.now || clock >= plan.binding.expires)
		die('preview_changed: Repair preview inputs changed during compilation');
	return plan;
}
export function frozen_status(io, view) {
	// Native loaders return fresh private values; validate and project them after releasing the lock.
	let frame = io.read_locked(() => ({ journal: io.load(), snapshot: io.snapshot(), boot: io.boot(), now: io.now() }), 5);
	return engine({ load: () => frame.journal, snapshot: () => frame.snapshot,
		boot: () => frame.boot, now: () => frame.now }).status(view, true);
}
export function frozen_agent_status(io) {
	let frame = frozen_status(io, 'agent'), result = frame.data;
	result.health = frame.active ? io.health(frame.active) : null;
	result.local = io.observe(frame.snapshot, 'agent', result.mesh_enabled ? result.intent : null);
	return result;
}
export function agent_status() {
	return frozen_agent_status({ read_locked, load, snapshot, boot, now, health, observe });
}
export function dispatch(method, args) {
	if (index(['repair_preview', 'local_overrides_preview'], method) >= 0) return frozen_repair_preview({
		locked, load, snapshot, settings, settings_source, approval_key, boot, now, capabilities
	}, args.intent, args.context);
	if (index(['status', 'diagnostics'], method) >= 0) {
		let view = method == 'diagnostics' ? 'diagnostics' : status_view(args?.view),
			frame = frozen_status({ read_locked, load:()=>load(true), snapshot, boot, now }, view), result = frame.data;
		result.capabilities = capabilities(frame.snapshot, true);
		result.health = frame.active ? health(frame.active) : null;
		result.local = observe(frame.snapshot, view);
		if (index(['wireless','diagnostics'],view)>=0) {
			let b=bus();
			result.local.roaming=steering_observation(frame.snapshot,result.intent,result.steering_managed,b);
			b?.disconnect();
		}
		if (method == 'diagnostics') {
			if (result.local.board) delete result.local.board.hostname;
			if (result.local.management) delete result.local.management.addresses;
			if (result.intent) {
				result.intent.name = '[redacted]';
				result.intent.wifi.ssid = '[redacted]';
			}
			if (result.active) delete result.active.ops;
		}
		return result;
	}
	return locked((service) => {
		if (method == 'preview') return service.preview(args.intent);
		if (method == 'mesh_preview') return service.mesh_preview(args.enabled, args.intent);
		if (method == 'rollback') return service.rollback(args.transaction_id);
		if (!recovery_available())
			die('daemon_unavailable: Recovery service is not running; changes are blocked');
		if (method == 'stage')
			return service.stage(args.intent, args.request_id, args.takeover, args.approval);
		if (method == 'local_overrides_stage')
			return service.local_overrides_stage(args.intent, args.request_id, args.takeover, args.approval, args.context);
		if (method == 'repair_stage')
			return service.repair_stage(args.intent, args.request_id, args.takeover, args.approval);
		if (method == 'mesh_stage')
			return service.mesh_stage(args.enabled, args.intent, args.request_id, args.takeover, args.approval);
		if (method == 'release') return service.release(args.request_id, args.takeover, args.approval);
		if (method == 'apply') return service.apply(args.transaction_id);
		if (method == 'confirm') return service.confirm(args.transaction_id);
		die('invalid_method: Unsupported method');
	});
}
