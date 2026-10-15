// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import { run } from 'mesh_process';
import { acquire } from './locking.uc';
import { note_state } from './event_log.uc';

const FILES = [
	'state.json',
	'identity.json',
	'cluster.json',
	'backhaul.json',
	'jobs.json',
	'device.key',
	'device.crt',
	'network-ca.key',
	'network-ca.crt',
	'join-ca.crt'
];
export function read(name) {
	if (index(FILES, name) < 0) die('invalid_file: Unknown state file');
	let dir = fs.lstat('/etc/mesh-manager');
	if (dir && (dir.type != 'directory' || dir.uid != 0 || dir.mode & 0077))
		die('storage_error: Unsafe state directory');
	let st = fs.lstat('/etc/mesh-manager/' + name);
	if (!st) return null;
	if (st.type != 'file' || st.uid != 0 || st.mode & 0077 || st.size > 1024 * 1024)
		die('storage_error: Unsafe state file');
	let content = fs.readfile('/etc/mesh-manager/' + name);
	// Missing and unreadable have different recovery semantics. An existing file
	// must never turn into a fresh identity or empty controller state on I/O error.
	if (type(content) != 'string' || !length(content) || length(content) > 1024 * 1024)
		die('storage_error: Cannot read persistent state file');
	return content;
}
export function write(name, content) {
	if (
		index(FILES, name) < 0 ||
		type(content) != 'string' ||
		!length(content) ||
		length(content) > 1024 * 1024
	)
		die('invalid_file: Invalid state payload');
	let result = run(['/usr/libexec/mesh-manager-store', name], content, 5000);
	if (result?.code != 0) die('storage_error: Durable state write failed');
}
// Private raw replacement. Expected bytes travel over stdin, never argv, and
// the native helper checks them under its existing directory writer lock.
export function write_cas(name, expected, content, timeout_ms) {
	if (index(FILES, name) < 0 || expected != null && (type(expected) != 'string' ||
		!length(expected) || length(expected) > 262144) || type(content) != 'string' ||
		!length(content) || length(expected || '') + length(content) > 1024 * 1024 ||
		type(timeout_ms) != 'int' || timeout_ms < 1 || timeout_ms > 5000)
		die('invalid_file: Invalid private state replacement');
	if (read(name) !== expected) die('storage_conflict: Original raw state changed before replacement');
	let result = run(['/usr/libexec/mesh-manager-store', '--cas', name,
		'' + (expected == null ? -1 : length(expected))], (expected || '') + content, timeout_ms);
	if (result?.code === 2) die('storage_conflict: Original raw state changed during replacement');
	if (result?.code !== 0) die('storage_error: Private durable replacement was not confirmed');
	if (read(name) !== content) die('storage_conflict: Durable replacement readback was changed');
}
export function remove_ca_key(expected) {
	if (type(expected)!='string' || !length(expected) || length(expected)>8192 || read('network-ca.key')!==expected)
		die('storage_conflict: Transferred signing key changed before retirement');
	let result=run(['/usr/libexec/mesh-manager-store','--remove-cas','network-ca.key',''+length(expected)],expected,5000);
	if(result?.code===2)die('storage_conflict: Transferred signing key changed during retirement');
	if(result?.code!==0 || read('network-ca.key')!==null)die('storage_error: Signing key retirement was not confirmed');
}
export function load(name) {
	let content = read(name);
	if (content == null) return null;
	try {
		let result = json(content);
		if (type(result) != 'object') die('Invalid persistent object');
		return result;
	} catch (e) {
		die('corrupt_state: Invalid persistent state');
	}
}
export function save(name, state) {
	write(name, sprintf('%J', state));
	note_state(name,state);
}
export function random(bytes) {
	let f = fs.open('/dev/urandom', 'r'),
		data = f?.read(bytes);
	f?.close();
	if (length(data) != bytes) die('entropy_error: Device entropy unavailable');
	return hexenc(data);
}
export function now() {
	let s = fs.readfile('/proc/uptime');
	if (!s || !match(s, /^[0-9]+\.[0-9]+ /)) die('clock_error: Monotonic clock unavailable');
	return +split(s, ' ')[0];
}
export function boot() {
	let id = trim(fs.readfile('/proc/sys/kernel/random/boot_id') || '');
	if (!match(id, /^[0-9a-f-]{36}$/)) die('clock_error: Boot identity unavailable');
	return id;
}
export function locked(callback, attempts) {
	let lock = fs.open('/var/run/mesh-manager-cluster.lock', 'a', 0600);
	if (!lock) die('storage_error: Cluster lock unavailable');
	if (!acquire(lock, attempts)) {
		lock.close();
		die('busy: Cluster request in progress');
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
