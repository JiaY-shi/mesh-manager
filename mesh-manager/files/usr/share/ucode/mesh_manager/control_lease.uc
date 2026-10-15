// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone } from './model.uc';
import { control_addresses } from './backhaul.uc';

function pair(slot) {
	let third = int(slot / 250) + 1, last = slot % 250 + 1;
	return { wired: '169.254.' + third + '.' + last,
		wireless: '169.254.' + (third + 128) + '.' + last };
}
function slot(lease) {
	if (type(lease) != 'object' || length(keys(lease)) != 2 || type(lease.wired) != 'string')
		die('control_address_invalid: Invalid controller-assigned control addresses');
	let p = split(lease.wired, '.');
	if (length(p) != 4 || p[0] != '169' || p[1] != '254' ||
		int(p[2]) < 1 || int(p[2]) > 100 || int(p[3]) < 1 || int(p[3]) > 250)
		die('control_address_invalid: Control address is outside the reserved pool');
	let n = (int(p[2]) - 1) * 250 + int(p[3]) - 1, expected = pair(n);
	if (lease.wired != expected.wired || lease.wireless != expected.wireless)
		die('control_address_invalid: Control addresses must be a canonical pair');
	return n;
}
export function require_lease(lease) { slot(lease); return clone(lease); }

// This is pure: reading or polling must never initialize persistent leases.
// Legacy members keep their actual old addresses. A legacy collision requires
// an explicit migration, not choosing a different address during a status read.
export function lease_table(state) {
	if (type(state?.members) != 'object' || length(keys(state.members)) > 64)
		die('control_address_invalid: Invalid controller membership');
	if (index(keys(state), 'control_schema') >= 0 && state.control_schema !== 1)
		die('control_address_invalid: Unsupported controller control lease schema');
	let table = {}, used = {};
	if(state.reserved_control!=null)used[slot(require_lease(state.reserved_control))]='controller';
	for (let id in sort(keys(state.members))) {
		let legacy = control_addresses(id), member = state.members[id];
		if (type(member) != 'object') die('control_address_invalid: Invalid controller member');
		let has_lease = index(keys(member), 'control') >= 0;
		if (!has_lease && state.control_schema === 1)
			die('control_address_invalid: Assigned control address record is missing');
		let lease = has_lease ? require_lease(member.control) : legacy, n = slot(lease);
		if (used[n]) die('control_address_conflict: Controller control addresses are duplicated');
		used[n] = id; table[id] = clone(lease);
	}
	return table;
}
export function lease_for(state, id) {
	let lease = lease_table(state)[id];
	if (lease == null) die('not_authorized: Control address requires an enrolled node');
	return lease;
}
export function adopt_leases(state) {
	let table = lease_table(state);
	for (let id in keys(table)) state.members[id].control = table[id];
	state.control_schema = 1;
	return table;
}
export function allocate_lease(state, id) {
	let seed = slot(control_addresses(id)), table = lease_table(state), used = {};
	if(state.reserved_control!=null)used[slot(require_lease(state.reserved_control))]=true;
	if (table[id]) return table[id];
	if (length(keys(table)) >= 64) die('limit_exceeded: Maximum 64 nodes');
	for (let lease in values(table)) used[slot(lease)] = true;
	// At most 64 occupied slots: N+1 probes always find an unused pair.
	for (let i = 0; i <= length(keys(table))+(state.reserved_control!=null ? 1 : 0); i++) {
		let next = (seed + i) % 25000;
		if (!used[next]) return pair(next);
	}
	die('control_address_conflict: No unused control address is available');
}
