// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import { clone } from './model.uc';
import * as durable from './durable.uc';

const DIRECTORY = '/var/run/mesh-manager-clients';
const FILE = DIRECTORY + '/observations.json';
const MAX_CLIENTS = 128;
const MAX_EVENTS = 128;
const ONLINE_AGE = 15;
const MAX_NODES = 65;
const MAX_BYTES = 2 * 1024 * 1024;
function unavailable() { die('clients_unavailable: Client observation storage is unavailable'); }

export function sanitize_clients(raw) {
	let result = [], seen = {};
	if (type(raw) != 'array') return result;
	for (let client in raw) {
		if (length(result) >= MAX_CLIENTS) break;
		let address = type(client?.address) == 'string' ? lc(client.address) : '';
		if (!match(address, /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/) || seen[address] ||
			!match(client.interface || '', /^[a-zA-Z0-9_.-]{1,15}$/)) continue;
		seen[address] = true;
		push(result, {
			address,
			interface: client.interface,
			authorized: client.authorized === true,
			signal: type(client.signal) == 'int' && client.signal >= -127 &&
				client.signal <= 0 ? client.signal : null
		});
	}
	return result;
}

export function advance(previous, boot, node, reported, uptime, wall) {
	if (!match(node || '', /^[0-9a-f]{32}$/))
		die('invalid_identity: Invalid client observation source');
	let state = previous?.boot == boot && type(previous.nodes) == 'object' &&
		type(previous.events) == 'array' ? clone(previous) :
		{ boot, nodes: {}, events: [] };
	let current = sanitize_clients(reported);
	if (type(reported) != 'array' || length(current) != length(reported)) unavailable();
	// Expired observations cannot prove a departure or movement. Prune them so
	// repeated enroll/revoke cycles cannot grow the tmpfs collection indefinitely.
	for (let id in keys(state.nodes))
		if (uptime < state.nodes[id].seen || uptime - state.nodes[id].seen >= ONLINE_AGE)
			delete state.nodes[id];
	if (!state.nodes[node] && length(keys(state.nodes)) >= MAX_NODES) unavailable();
	let before = state.nodes[node]?.clients || [];
	let prior = {}, present = {};
	for (let other in keys(state.nodes))
		if (other != node) for (let client in state.nodes[other].clients) prior[client.address] = other;
	for (let client in current) present[client.address] = true;
	let old = {};
	for (let client in before) old[client.address] = true;
	for (let client in current) {
		if (old[client.address]) continue;
		let prior_node = prior[client.address];
		push(state.events, {
			kind: prior_node ? 'node_change' : 'associated',
			client: client.address,
			from: prior_node,
			to: node,
			at: wall
		});
	}
	for (let client in before)
		if (!present[client.address])
			push(state.events, {
				kind: 'disassociated', client: client.address,
				from: node, to: null, at: wall
			});
	state.nodes[node] = { seen: uptime, clients: current };
	if (length(state.events) > MAX_EVENTS)
		state.events = slice(state.events, length(state.events) - MAX_EVENTS);
	return state;
}

export function public_status(state, boot, uptime) {
	let result = { nodes: {}, samples: {}, events: [] };
	if (state?.boot != boot) return result;
	for (let id in keys(state.nodes || {})) {
		let entry = state.nodes[id];
		if (uptime >= entry.seen && uptime - entry.seen < ONLINE_AGE) {
			result.nodes[id] = entry.clients || [];
			result.samples[id] = { age_ms: int((uptime - entry.seen) * 1000) };
		}
	}
	result.events = slice(state.events || [], -MAX_EVENTS);
	return result;
}

// Validate old schema-1 tmpfs snapshots too; an upgrade preserves actual events.
export function decode(raw) {
	if (raw == null) return null;
	if (type(raw) != 'string' || length(raw) > MAX_BYTES) unavailable();
	let state;
	try { state = json(raw); } catch (e) { unavailable(); }
	if (type(state) != 'object' || type(state.boot) != 'string' || length(state.boot) > 64 ||
		type(state.nodes) != 'object' || length(keys(state.nodes)) > MAX_NODES ||
		type(state.events) != 'array' || length(state.events) > MAX_EVENTS) unavailable();
	for (let id in keys(state.nodes)) {
		let entry = state.nodes[id];
		if (!match(id, /^[0-9a-f]{32}$/) || type(entry) != 'object' ||
			index(['int','double'], type(entry.seen)) < 0 || entry.seen < 0 ||
			type(entry.clients) != 'array' || length(entry.clients) > MAX_CLIENTS ||
			length(sanitize_clients(entry.clients)) != length(entry.clients)) unavailable();
		entry.clients = sanitize_clients(entry.clients);
	}
	for (let entry in state.events)
		if (type(entry) != 'object' || index(['associated','disassociated','node_change'], entry.kind) < 0 ||
			!match(entry.client || '', /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/) ||
			entry.from != null && !match(entry.from, /^[0-9a-f]{32}$/) ||
			entry.to != null && !match(entry.to, /^[0-9a-f]{32}$/) ||
			entry.from == null && entry.to == null || type(entry.at) != 'int' || entry.at < 0) unavailable();
	return { boot: state.boot, nodes: state.nodes, events: map(state.events, row =>
		({kind:row.kind,client:row.client,from:row.from,to:row.to,at:row.at})) };
}
function safe(path, kind, optional) {
	let st = fs.lstat(path);
	if (!st && optional) return null;
	if (st?.type != kind || st.uid != 0 || st.mode & 0077 || kind == 'file' && st.size > MAX_BYTES) unavailable();
	return st;
}
function directory(create) {
	if (!fs.lstat(DIRECTORY)) {
		if (!create) return false;
		if (!fs.mkdir(DIRECTORY, 0700) && !fs.lstat(DIRECTORY)) unavailable();
	}
	safe(DIRECTORY, 'directory'); return true;
}
function read() {
	if (!directory(false) || !safe(FILE, 'file', true)) return null;
	let f = fs.open(FILE, 'r'), raw = f?.read(MAX_BYTES + 1); f?.close();
	if (type(raw) != 'string') unavailable();
	return decode(raw);
}
export function observe(node, clients) {
	let lock;
	try {
		directory(true); safe(DIRECTORY + '/lock', 'file', true);
		lock = fs.open(DIRECTORY + '/lock', 'ae', 0600);
		if (!lock?.lock('xn')) { lock?.close(); return false; }
		let state = advance(read(), durable.boot(), node, clients, durable.now(), time()),
			data = sprintf('%J', state), temp = FILE + '.new';
		if (length(data) > MAX_BYTES) unavailable();
		if (safe(temp, 'file', true) && !fs.unlink(temp)) unavailable();
		let file = fs.open(temp, 'wx', 0600);
		if (!file) unavailable();
		let ok = file.write(data) == length(data) && file.flush(); file.close();
		if (!ok || !fs.rename(temp, FILE)) unavailable();
		lock.close(); return true;
	} catch (e) {
		lock?.close();
		// Telemetry cannot prevent a transaction or independent recovery.
		return false;
	}
}
export function status() {
	return public_status(read(), durable.boot(), durable.now());
}
