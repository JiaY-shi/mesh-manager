// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { sha256, hmac, constant_equal } from 'mesh_crypto';
import { canonical } from './model.uc';

const FIELDS = {
	local: ['id', 'status', 'version', 'kind', 'failure', 'conflicts', 'timestamp'],
	cluster: ['id', 'phase', 'version', 'failure', 'nodes', 'timestamp'],
	repair: ['id', 'node_id', 'purpose', 'status', 'version', 'error', 'conflicts', 'timestamp'],
	lifecycle: ['id', 'enabled', 'phase', 'failure', 'nodes', 'timestamp'],
	metadata: ['id','node_id','previous_name','name','version','status','timestamp']
};
function invalid() { die('invalid_request: Invalid history page request'); }
function expired() { die('cursor_expired: History changed or the page expired; reload from the first page'); }
function encode(value) { return sprintf('%J', canonical(value)); }
function project(entry, fields) {
	if (type(entry) != 'object') die('corrupt_state: Invalid history record');
	let result = {};
	for (let field in fields) {
		let value = entry[field] ?? null;
		if (index(['nodes', 'conflicts'], field) >= 0) {
			if (value == null) value = [];
			if (type(value) != 'array' || length(value) > (field == 'nodes' ? 64 : 2048))
				die('corrupt_state: Invalid history details');
			result[field] = map(value, row => {
				if (type(row) != 'object') die('corrupt_state: Invalid history detail');
				let item = {};
				for (let key in field == 'nodes' ? ['id', 'status', 'error'] : ['path', 'message']) {
					if (row[key] != null && (type(row[key]) != 'string' || length(row[key]) > 2048))
						die('corrupt_state: Invalid history detail field');
					item[key] = row[key] ?? null;
				}
				return item;
			});
		} else {
			if (value != null && index(['string', 'int', 'double', 'bool'], type(value)) < 0 ||
				type(value) == 'string' && length(value) > 2048)
				die('corrupt_state: Invalid history field');
			result[field] = value;
		}
	}
	return result;
}

export function history_revision(group, source, boot) {
	if (!FIELDS[group]) invalid();
	if (type(source) != 'array' || length(source) > 32) die('corrupt_state: Invalid history collection');
	return sha256(encode({ boot, group, scope: null,
		records: reverse(map(source, entry => project(entry, FIELDS[group]))) }));
}

// Stateless cursors retain no session results and never write flash. The process
// key changes on rpcd restart, so a prior process's cursor cannot silently resume.
export function history_pager(io, profile) {
	let key;
	let definitions=profile?.fields || FIELDS,maximum=profile?.maximum || 32,scope=profile?.scope ?? null;
	return (args, sid) => {
		if (type(args) != 'object' || length(filter(keys(args), name =>
			index(['group', 'cursor', 'limit', 'fields', 'if_revision', 'ubus_rpc_session'], name) < 0))) invalid();
		let group = args.group, limit = args.limit ?? 5, fields = args.fields;
		if (type(group) != 'string' || !definitions[group] || type(limit) != 'int' || limit < 1 || limit > 50 ||
			type(sid) != 'string' || !match(sid, /^[0-9a-f]{32}$/)) invalid();
		if (fields == null || type(fields) == 'array' && !length(fields)) fields = definitions[group];
		if (type(fields) != 'array' || length(fields) > length(definitions[group]) ||
			length(filter(fields, name => type(name) != 'string' || index(definitions[group], name) < 0)) ||
			length(uniq(fields)) != length(fields)) invalid();
		fields = sort([...fields]);
		let conditional = args.if_revision ?? '', token = args.cursor ?? '';
		if (type(conditional) != 'string' || conditional != '' && !match(conditional, /^[0-9a-f]{64}$/) ||
			type(token) != 'string' || length(token) > 4096) invalid();
		let clock = int(io.now() * 1000), boot = io.boot(), old = null;
		key ??= io.random(32);
		if (type(key) != 'string' || length(key) != 64) die('entropy_error: History cursor entropy unavailable');
		let owner = hmac(key, sid);
		if (token) {
			let parts = split(token, '.');
			if (length(parts) != 2 || !match(parts[0], /^[0-9a-f]+$/) || length(parts[0]) % 2 ||
				!match(parts[1], /^[0-9a-f]{64}$/) || !constant_equal(hmac(key, parts[0]), parts[1])) expired();
			try { old = json(hexdec(parts[0])); } catch (e) { expired(); }
			if (old?.boot != boot || old.owner != owner || old.group != group || old.limit != limit || encode(old.scope) != encode(scope) ||
				encode(old.fields) != encode(fields) || type(old.offset) != 'int' || old.offset < 0 ||
				type(old.expires) != 'int' || old.expires <= clock || old.expires > clock + 300000) expired();
		}
		let source = io.records(group);
		if (type(source) != 'array' || length(source) > maximum) die('corrupt_state: Invalid history collection');
		// Revision covers all PUBLIC summary fields even when fields selects a subset.
		// Private plans are deliberately never part of a history response or cursor.
		let records = reverse(map(source, entry => project(entry, definitions[group]))),
			// Client membership remains stable while RSSI changes. Its cursor binds
			// membership; the conditional page revision still covers current metrics.
			binding = profile?.cursor_fields ? map(records, entry => project(entry, profile.cursor_fields)) : records,
			snapshot_revision = sha256(encode({ boot, group, scope, records: binding })), offset = old?.offset || 0,
			revision = sha256(encode({ snapshot_revision, fields, limit, offset,
				page: profile?.cursor_fields ? slice(records, offset, offset + limit) : null }));
		if (old && (old.snapshot_revision != snapshot_revision || offset >= length(records) && offset != 0)) expired();
		function cursor(offset) {
			let payload = hexenc(encode({ boot, owner, group, scope, limit, fields, snapshot_revision, offset, expires: clock + 300000 }));
			return payload + '.' + hmac(key, payload);
		}
		let result = { group, boot_id: boot, revision, observed_uptime_ms: clock, stale: false,
			total: length(records), offset, limit, cursor: cursor(offset),
			next_cursor: offset + limit < length(records) ? cursor(offset + limit) : null,
			previous_cursor: offset > 0 ? cursor(max(0, offset - limit)) : null,
			unchanged: conditional == revision };
		if (!profile) result.clear_revision = snapshot_revision;
		if (!result.unchanged) result.items = map(slice(records, offset, offset + limit), entry => project(entry, fields));
		if (length(encode(result)) > 128 * 1024) die('result_too_large: History page exceeds the response limit');
		return result;
	};
}
