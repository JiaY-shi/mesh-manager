// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { sha256 } from 'mesh_crypto';
import { clone } from './model.uc';
import { history_revision } from './history_page.uc';

export function history_field(group) {
	let field = {local:'history', cluster:'history', repair:'repair_history',
		lifecycle:'lifecycle_history', metadata:'metadata_history'}[group];
	if (!field) die('invalid_request: Unknown history group');
	return field;
}
function retained(s, group) {
	let all=s.history_retention;
	if (all == null) return {requests:[]};
	if (type(all) != 'object' || length(filter(keys(all), key =>
		index(['local','cluster','repair','lifecycle','metadata'],key)<0)))
		die('corrupt_state: Invalid history retention');
	let item=all[group] ?? {requests:[]};
	if (type(item) != 'object' || length(filter(keys(item), key =>
		index(['requests','version','restore','clear'],key)<0)) || type(item.requests) != 'array' ||
		length(item.requests)>32 || length(uniq(item.requests))!=length(item.requests) ||
		length(filter(item.requests,id=>type(id)!='string' || !match(id,/^[a-zA-Z0-9_-]{1,96}$/))) ||
		item.version != null && (type(item.version)!='int' || item.version<0) ||
		item.restore != null && (group!='local' || type(item.restore)!='object' || length(keys(item.restore))!=3 ||
			!match(item.restore.id || '',/^[a-zA-Z0-9_-]{1,96}$/) ||
			!match(item.restore.request_id || '',/^[a-zA-Z0-9_-]{16,96}$/) ||
			type(item.restore.version)!='int' || item.restore.version<1) ||
		item.clear != null && (type(item.clear)!='object' || length(keys(item.clear))!=4 ||
			!match(item.clear.id || '',/^[0-9a-f]{32}$/) || !match(item.clear.owner || '',/^[0-9a-f]{64}$/) ||
			!match(item.clear.revision || '',/^[0-9a-f]{64}$/) || type(item.clear.count)!='int' ||
			item.clear.count<1 || item.clear.count>32))
		die('corrupt_state: Invalid retained history receipt');
	return item;
}
export function history_used(s, group, id) {
	let records=s[history_field(group)] || [];
	return index(retained(s,group).requests,id)>=0 ||
		length(filter(records,row=>(group=='local' ? row.request_id : row.id)==id))>0;
}
export function history_version(s) { return retained(s,'cluster').version || 0; }
export function history_restored(s, proof) {
	if (!proof) return false;
	let row=retained(s,'local').restore;
	return row && row.id==proof.id && row.request_id==proof.request_id && row.version===proof.version ||
		length(filter(s.history,h=>h.id==proof.id && h.request_id==proof.request_id &&
			h.kind=='release' && h.status=='committed' && h.version===proof.version))>0;
}
export function validate_history_clear(args) {
	if (type(args)!='object' || length(filter(keys(args),key=>
		index(['group','expected_revision','request_id','ubus_rpc_session'],key)<0)) ||
		type(args.group)!='string' || type(args.expected_revision)!='string' ||
		!match(args.expected_revision,/^[0-9a-f]{64}$/) || type(args.request_id)!='string' ||
		!match(args.request_id,/^[0-9a-f]{32}$/) || args.ubus_rpc_session != null &&
		(type(args.ubus_rpc_session)!='string' || !match(args.ubus_rpc_session,/^[0-9a-f]{32}$/)))
		die('invalid_request: Invalid history cleanup request');
	history_field(args.group);
}
export function history_cleanup_idle(s) {
	if (s.active && (s.active.status != null ?
		index(['committed','rolled_back','rollback_conflict','expired'],s.active.status)<0 :
		index(['complete','partial','failed','rolled_back','expired'],s.active.phase)<0) ||
		s.lifecycle && index(['complete','partial','failed','rolled_back','expired','cancelled'],s.lifecycle.phase)<0 ||
		length(filter(values(s.members || {}),m=>m.repair &&
			index(['committed','rolled_back','rollback_conflict','failed','expired'],m.repair.status)<0)))
		die('busy: Wait for pending configuration operations before clearing history');
}
// Caller holds the same exclusive lock as transaction writers. Only summary
// arrays change: active journals, snapshots, ownership, identity and commands stay.
export function clear_retained_history(s, args, boot) {
	validate_history_clear(args);
	let group=args.group, field=history_field(group), rows=s[field] || [], item=clone(retained(s,group)),
		owner=sha256(args.ubus_rpc_session || '00000000000000000000000000000000');
	if (item.clear?.id==args.request_id) {
		if (item.clear.owner!=owner || item.clear.revision!=args.expected_revision)
			die('request_reused: Cleanup request belongs to another approval');
		return {group,cleared:item.clear.count,replayed:true};
	}
	if (history_revision(group,rows,boot)!=args.expected_revision)
		die('preview_changed: History changed; refresh and confirm again');
	history_cleanup_idle(s);
	if (!length(rows)) return {group,cleared:0,replayed:false};
	for (let row in rows) {
		let id=group=='local' ? row.request_id : row.id;
		if (type(id)!='string' || !match(id,/^[a-zA-Z0-9_-]{1,96}$/))
			die('corrupt_state: History request receipt unavailable');
		item.requests=filter(item.requests,old=>old!=id); push(item.requests,id);
		if (length(item.requests)>32) shift(item.requests);
		if (group=='cluster') {
			if (type(row.version)!='int' || row.version<0) die('corrupt_state: Invalid historical intent version');
			item.version=max(item.version || 0,row.version);
		}
		if (group=='local' && s.restore_checkpoint && row.id==s.restore_checkpoint.id &&
			row.request_id==s.restore_checkpoint.request_id && row.kind=='release' &&
			row.status=='committed' && row.version===s.restore_checkpoint.version)
			item.restore={id:row.id,request_id:row.request_id,version:row.version};
	}
	item.clear={id:args.request_id,owner,revision:args.expected_revision,count:length(rows)};
	s.history_retention ||= {}; s.history_retention[group]=item; s[field]=[];
	return {group,cleared:length(rows),replayed:false};
}
