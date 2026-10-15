// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal, public_op } from './model.uc';
import { require_anchor } from './authority.uc';
import {migration_pending as pending_migration} from './authority_model.uc';
import { require_lease } from './control_lease.uc';
import { private_address } from './identity.uc';

export const MIGRATION_PROTOCOL = 1;
export const TRANSFER_LIMIT = 262144;
export const CHUNK_SIZE = 8192;
export function migration_id(value) { return type(value)=='string' && length(value)==32 && match(value,/^[0-9a-f]{32}$/)!=null; }
export function migration_hash(value) { return type(value)=='string' && length(value)==64 && match(value,/^[0-9a-f]{64}$/)!=null; }
function full(value,pattern) { return type(value)=='string' && match(value,pattern)?.[0]===value; }
export function migration_binding(value) {
	return type(value)=='object' && migration_id(value.controller_id) && migration_id(value.network_id) &&
		private_address(value.address) && match(value.control_address || '',/^169\.254\.[0-9]{1,3}\.[0-9]{1,3}$/) &&
		private_address(value.control_address) && migration_hash(value.controller_certificate) && migration_hash(value.ca_fingerprint) &&
		type(value.epoch)=='int' && value.epoch>=1;
}
function review_plan(plan) { return plan ? {...clone(plan),ops:filter(clone(plan.ops || []),op=>op.changed!==false)} : null; }
export function public_migration(m, plans) {
	if (!m) return null;
	let result={id:m.id,phase:m.phase,epoch:m.epoch,source:m.source,target:m.target,
		anchor:m.anchor ? {id:m.anchor.id,address:m.anchor.address,gateway:m.anchor.gateway} : null,
		version:m.version,created:m.created,target_address:m.binding?.address || null,fenced:m.fenced===true,failure:m.failure || null,
		nodes:map(keys(m.nodes || {}),id=>({id,status:m.nodes[id].status,error:m.nodes[id].error || null,
			...(plans===false ? {has_plan:m.nodes[id].plan!=null} : {plan:review_plan(m.nodes[id].plan)})})),
		joined:clone(m.joined || []),
		cancel_allowed:m.fenced!==true && index(['preflight','ready','applying','failed','cancelling'],m.phase)>=0,
		invalidates_enrollment:true};
	if (m.root) result.root = {status:m.root.status,error:m.root.error || null,
		...(plans===false ? {has_plan:m.root.plan!=null} : {plan:review_plan(m.root.plan)})};
	return result;
}
export function migration_pending(m) { return pending_migration(m); }
export function migration_candidate(unified, settings, id, anchor, target, control, construct) {
	anchor=require_anchor(anchor);
	return construct(unified,settings,id==target,anchor.gateway,id,
		id==anchor.id ? null : require_lease(control),anchor);
}
function map_to_nodes(members) {
	let result={};for(let id in keys(members))if(members[id].authorized)result[id]={status:'pending'};return result;
}
export function transfer_state(state, migration, own_certificate, settings, control) {
	let s=clone(state),target=s.members[migration.target];
	if (!target?.authorized || !migration_hash(own_certificate) || !migration_binding(migration.binding))
		die('migration_conflict: Authorized transfer identities changed');
	delete s.migration;
	// Completed configuration history is preserved; enrollment tokens belong to
	// the previous controller and are explicitly invalidated in the preview.
	s.invitations=[];s.requests={};
	s.reserved_control=migration.target==migration.anchor.id ? null : require_lease(target.control);
	s.members[migration.source]={id:migration.source,name:settings.name || state.intent.name,
		certificate:own_certificate,authorized:true,status:'authorized',version:state.version,
		control:require_lease(control),control_protocol:1,control_configured:true,control_bound:true,
		joined:time(),mesh_paused:false};
	delete s.members[migration.target];
	s.migration={id:migration.id,phase:'switching',source:migration.source,target:migration.target,
		epoch:migration.epoch,version:migration.version,created:migration.created,anchor:clone(migration.anchor),
		binding:clone(migration.binding),joined:[],nodes:map_to_nodes(s.members),
		fenced:true,token:migration.token,hash:migration.hash || null};
	return s;
}

export function migration_receipt(m) {
	if (!m) return null;
	return {protocol:1,id:m.id,phase:m.phase,epoch:m.epoch,
		transaction_id:m.transaction_id || null,received:length(m.chunks || []),
		hash:m.hash || null,error:m.error || null,plan:m.phase=='ready' ? clone(m.plan) : null};
}
export function sanitize_migration_receipt(r) {
	if(type(r)!='object' || length(keys(r))!=9 || r.protocol!==1 || !migration_id(r.id) ||
		index(['preparing','ready','applying','awaiting_confirm','committed','cancelling','cancelled','error',
			'transferring','transferred','promoting','switched','finishing','complete','expired'],r.phase)<0 ||
		type(r.epoch)!='int' || r.epoch<2 || type(r.received)!='int' || r.received<0 || r.received>32 ||
		r.hash!=null && !migration_hash(r.hash) || r.error!=null && !full(r.error,/^[a-z_]{1,96}$/) ||
		r.transaction_id!=null && !full(r.transaction_id,/^[a-zA-Z0-9_-]{16,96}$/))return null;
	let plan=r.plan;
	if(plan!=null) {
		if(r.phase!='ready' || type(plan)!='object' ||
			length(filter(keys(plan),k=>index(['ops','errors','conflicts','warnings','dangerous','version','binding'],k)<0)) ||
			type(plan.ops)!='array' || length(plan.ops)>512 || type(plan.errors)!='array' || length(plan.errors)>64 ||
			type(plan.conflicts)!='array' || length(plan.conflicts)>512 || type(plan.warnings)!='array' || length(plan.warnings)>64 ||
			type(plan.version)!='int' || plan.version<0 || type(plan.binding)!='object' || length(keys(plan.binding))!=3 ||
			!full(plan.binding.boot,/^[a-zA-Z0-9_-]{1,64}$/) || type(plan.binding.expires)!='int' ||
			plan.binding.expires<0 || !migration_hash(plan.binding.token) || length(sprintf('%J',plan))>38000 ||
			length(filter(plan.ops,o=>type(o)!='object' || !full(o.config,/^[a-zA-Z0-9_-]{1,64}$/) ||
				!full(o.section,/^[a-zA-Z0-9_-]{1,64}$/) || o.option!=null && !full(o.option,/^[a-zA-Z0-9_-]{1,64}$/))))return null;
		plan={...clone(plan),ops:map(plan.ops,public_op)};
	}
	return {protocol:1,id:r.id,phase:r.phase,epoch:r.epoch,received:r.received,hash:r.hash,
		transaction_id:r.transaction_id,error:r.error,plan};
}

export function validate_chunk(m, command) {
	if (!migration_hash(command.hash) || type(command.total)!='int' || command.total<1 ||
		command.total>int((TRANSFER_LIMIT+CHUNK_SIZE-1)/CHUNK_SIZE) || type(command.index)!='int' ||
		command.index<0 || command.index>=command.total || type(command.data)!='string' ||
		!length(command.data) || length(command.data)>CHUNK_SIZE ||
		command.index<command.total-1 && length(command.data)!=CHUNK_SIZE ||
		m.hash!=null && m.hash!=command.hash || m.total!=null && m.total!=command.total)
		die('migration_conflict: Transferred authority chunk does not match the original transfer');
	let received=length(m.chunks || []);
	if (command.index>received || command.index<received && m.chunks[command.index]!=command.data)
		die('migration_conflict: Authority chunks must be exact and ordered');
	return command.index==received;
}
export function validate_transfer(payload, pending, identity, ca, fingerprint) {
	if (type(payload)!='object' || length(keys(payload))!=9 || payload.schema!==1 ||
		payload.id!==pending.id || payload.epoch!==pending.epoch || payload.network_id!==identity.binding?.network_id ||
		!equal(payload.anchor,pending.anchor) || !equal(payload.binding,pending.binding) || payload.binding.controller_id!==identity.id ||
		payload.ca_crt!==ca || fingerprint(payload.ca_crt)!==identity.binding.ca_fingerprint ||
		type(payload.ca_key)!='string' || !length(payload.ca_key) || length(payload.ca_key)>8192 ||
		payload.cluster?.schema!==1 || payload.cluster.version!==pending.version ||
		payload.cluster.migration?.id!==pending.id || payload.cluster.migration?.target!==identity.id ||
		payload.cluster.members?.[identity.id]!=null || payload.cluster.members?.[pending.source]?.authorized!==true ||
		length(keys(payload.cluster.members || {}))>64 || length(sprintf('%J',payload))>TRANSFER_LIMIT)
		die('migration_conflict: Transferred authority does not match the reviewed network');
	return clone(payload);
}
