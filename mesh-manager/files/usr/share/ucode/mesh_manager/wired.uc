// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import { run } from 'mesh_process';
import { private_address } from './identity.uc';

function command(args) {
	let result = run(args, '', 1500);
	if (result?.code != 0) return null;
	try { return json(result.stdout); } catch (e) { return null; }
}
export function bridge_port(address, device, neighbors, fdb) {
	let neighbor = filter(neighbors || [], (n) => n.dst == address &&
		match(n.lladdr || '', /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/) &&
		!length(filter(n.state || [], (s) => index(['FAILED', 'INCOMPLETE'], s) >= 0)))[0];
	if (!neighbor) return null;
	let entries = filter(fdb || [], (e) => lc(e.mac || '') == lc(neighbor.lladdr) &&
		(e.ifname || e.dev) != device && (!e.master || e.master == device) &&
		index(e.flags || [], 'self') < 0);
	let ports = uniq(map(entries, (e) => e.ifname || e.dev));
	return length(ports) == 1 && match(ports[0] || '', /^[a-zA-Z0-9_-]{1,15}$/) ? ports[0] : null;
}
export function physical_port(address, interface_name) {
	if (!private_address(address)) return null;
	let route = command(['/usr/libexec/ip-full', '-j', 'route', 'get', address])?.[0];
	if (!route || route.gateway || interface_name && route.dev != interface_name ||
		!match(route.dev || '', /^[a-zA-Z0-9_.-]{1,15}$/)) return null;
	let device = route.dev;
	if (fs.access('/sys/class/net/' + device + '/phy80211')) return null;
	if (fs.access('/sys/class/net/' + device + '/bridge')) {
		device = bridge_port(address, device,
			command(['/usr/libexec/ip-full', '-j', 'neigh', 'show', 'to', address, 'dev', device]),
			command(['/usr/sbin/bridge', '-j', 'fdb', 'show', 'br', device]));
	}
	if (!match(device || '', /^[a-zA-Z0-9_-]{1,15}$/) ||
		fs.access('/sys/class/net/' + device + '/phy80211') ||
		!fs.access('/sys/class/net/' + device + '/device') && !fs.access('/sys/class/net/' + device + '/dsa') ||
		trim(fs.readfile('/sys/class/net/' + device + '/carrier') || '') != '1') return null;
	return device;
}

// Enrollment may originate on a wired or Wi-Fi port of the management LAN.
// A routed/WAN source is never accepted just because its address is private.
export function lan_source(address, bridge) {
	if (!private_address(address) || !match(bridge || '', /^[a-zA-Z0-9_.-]{1,15}$/) ||
		!fs.access('/sys/class/net/' + bridge + '/bridge')) return false;
	let route = command(['/usr/libexec/ip-full', '-j', 'route', 'get', address])?.[0];
	if (!route || route.gateway || route.dev != bridge) return false;
	let port = bridge_port(address, bridge,
		command(['/usr/libexec/ip-full', '-j', 'neigh', 'show', 'to', address, 'dev', bridge]),
		command(['/usr/sbin/bridge', '-j', 'fdb', 'show', 'br', bridge]));
	return port != null && fs.access('/sys/class/net/' + bridge + '/brif/' + port);
}
