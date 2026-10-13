// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { history_used } from './history_retention.uc';
import { sha256, hmac, constant_equal } from 'mesh_crypto';
import { clone, canonical, valid_text } from './model.uc';
import { lifecycle_busy, configuration_busy } from './lifecycle.uc';

function encode(value) { return sprintf('%J',canonical(value)); }
function public_record(row) {
	return {id:row.id,node_id:row.node_id,previous_name:row.previous_name,name:row.name,
		version:row.version,status:'committed',timestamp:row.timestamp};
}
// The caller holds the cluster lock. Name, monotonic metadata version and receipt
// are published in one existing durable atomic file; no UCI or reload is involved.
export function node_metadata(io) {
	function state() {
		let identity=io.load('identity.json'),s=io.load('cluster.json');
		if(identity?.role!='root')die('not_controller: Only the controller can name its members');
		if(type(s?.members)!='object' || type(s.metadata_revision ?? 0)!='int' ||
			(s.metadata_revision ?? 0)<0 || (s.metadata_revision ?? 0)>2147483647 ||
			type(s.metadata_history ?? [])!='array' || length(s.metadata_history ?? [])>32)
			die('corrupt_state: Invalid node metadata journal');
		let previous=0,seen={};
		for(let row in s.metadata_history || []) {
			if(type(row)!='object' || length(keys(row))!=8 || !match(row.id || '',/^[0-9a-f]{32}$/) || seen[row.id] ||
				!match(row.node_id || '',/^[0-9a-f]{32}$/) || !match(row.fingerprint || '',/^[0-9a-f]{64}$/) ||
				!valid_text(row.name,1,64) || !valid_text(row.previous_name,0,64) || row.status!='committed' ||
				type(row.version)!='int' || row.version<=previous || row.version>s.metadata_revision ||
				type(row.timestamp)!='int' || row.timestamp<0)
				die('corrupt_state: Invalid metadata receipt');
			previous=row.version;seen[row.id]=true;
		}
		return {identity,s};
	}
	function key() {
		let secret=io.read('device.key');
		if(type(secret)!='string' || length(secret)<32 || length(secret)>16384)die('identity_error: Metadata signing identity unavailable');
		return hmac(sha256(secret),'mesh-manager/node-name/v1');
	}
	function capture(data,node_id,name) {
		if(type(node_id)!='string' || !match(node_id,/^[0-9a-f]{32}$/))die('invalid_request: Invalid target node');
		if(!valid_text(name,1,64))die('invalid_name: Invalid node name');
		let member=data.s.members[node_id];
		if(!member)die('not_found: Node not found');
		if(member.authorized!==true)die('not_authorized: Node identity is no longer authorized');
		if(lifecycle_busy(data.s) || configuration_busy(data.s,io))die('busy: Another configuration transaction is active');
		return {node_id,previous_name:member.name || '',name,
			expected_revision:sha256(encode({controller_id:data.identity.id,network_id:data.identity.network_id,
				node_id,name:member.name,authorized:member.authorized,certificate:member.certificate,
				metadata_revision:data.s.metadata_revision || 0}))};
	}
	function preview(node_id,name) {
		let data=state(),body={schema:1,kind:'node_name',...capture(data,node_id,name),
			controller_id:data.identity.id,network_id:data.identity.network_id,boot:io.boot(),
			expires:int(io.now()*1000)+300000};
		return {...body,seal:hmac(key(),encode(body))};
	}
	function apply(args) {
		if(type(args)!='object' || length(filter(keys(args),name=>
			index(['request_id','approval','takeover','ubus_rpc_session'],name)<0)))die('invalid_request: Invalid name change request');
		if(args?.takeover!==true)die('takeover_required: Confirm the node name change');
		if(type(args.request_id)!='string' || !match(args.request_id,/^[0-9a-f]{32}$/))die('invalid_request: Invalid metadata request identity');
		let data=state(),plan=clone(args.approval),seal=plan?.seal;
		if(type(plan)!='object' || length(keys(plan))!=11 || type(seal)!='string' || length(seal)!=64 ||
			length(filter(keys(plan),name=>index(['schema','kind','node_id','previous_name','name','expected_revision',
				'controller_id','network_id','boot','expires','seal'],name)<0)) ||
			!valid_text(plan.name,1,64) || !valid_text(plan.previous_name,0,64) ||
			type(plan.boot)!='string' || length(plan.boot)>64 || type(plan.expires)!='int' ||
			type(plan.kind)!='string' || length(plan.kind)>16 || type(plan.schema)!='int' ||
			length(filter(['node_id','controller_id','network_id'],name=>type(plan[name])!='string' || !match(plan[name],/^[0-9a-f]{32}$/))) ||
			type(plan.expected_revision)!='string' || !match(plan.expected_revision,/^[0-9a-f]{64}$/))
			die('invalid_request: Invalid name approval');
		delete plan.seal;
		if(plan.schema!=1 || plan.kind!='node_name' || plan.controller_id!=data.identity.id || plan.network_id!=data.identity.network_id ||
			!constant_equal(hmac(key(),encode(plan)),seal))die('preview_changed: Node name approval is invalid');
		let fingerprint=sha256(encode(args.approval)),history=data.s.metadata_history || [];
		for(let row in history)if(row.id==args.request_id) {
			if(row.fingerprint!=fingerprint)die('request_reused: Request identity belongs to another change');
			return {...public_record(row),replayed:true};
		}
		if(history_used(data.s,'metadata',args.request_id))die('request_reused: Name request already completed');
		if(plan.boot!=io.boot() || type(plan.expires)!='int' || plan.expires<=int(io.now()*1000) ||
			plan.expires>int(io.now()*1000)+300000)die('preview_expired: Preview expired; review the name again');
		if((data.s.metadata_revision || 0)>=2147483647)die('quota_exceeded: Node metadata version limit reached');
		let current=capture(data,plan.node_id,plan.name);
		if(current.expected_revision!=plan.expected_revision || current.previous_name!=plan.previous_name)
			die('preview_changed: Node name or identity changed after preview');
		let row={id:args.request_id,node_id:plan.node_id,previous_name:current.previous_name,name:plan.name,
			version:(data.s.metadata_revision || 0)+1,status:'committed',timestamp:time(),fingerprint};
		data.s.members[plan.node_id].name=plan.name;
		data.s.metadata_revision=row.version;
		data.s.metadata_history=[...history,row];
		if(length(data.s.metadata_history)>32)shift(data.s.metadata_history);
		io.save('cluster.json',data.s);
		return {...public_record(row),replayed:false};
	}
	return {preview,apply};
}
