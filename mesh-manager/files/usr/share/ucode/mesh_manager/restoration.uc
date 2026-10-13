// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal, canonical } from './model.uc';
import { sha256 } from 'mesh_crypto';
import { loss_receipt } from './controller_loss.uc';

const FINAL = ['committed','failed','rolled_back','rollback_conflict','expired','no_change','error'];
const COORDINATED_FINAL = ['complete','failed','partial','cancelled','expired','rolled_back'];
function token(value) { return type(value) == 'string' && length(value) >= 16 && length(value) <= 64 &&
	match(value,/^[A-Za-z0-9_-]+$/) != null; }

function binding(root, member) {
	if (root?.role != 'root' || !match(root.id || '', /^[0-9a-f]{32}$/) ||
		!match(root.network_id || '', /^[0-9a-f]{32}$/) ||
		!match(member?.id || '', /^[0-9a-f]{32}$/) ||
		!match(member.certificate || '', /^[0-9a-f]{64}$/)) return null;
	return {controller_id:root.id,network_id:root.network_id,node_id:member.id,
		certificate:member.certificate,control:clone(member.control ?? null)};
}

function restored(report) {
	let tx=report?.transaction;
	return report?.configured === true && report.mesh_enabled === false &&
		type(report.drift) == 'array' && !length(report.drift) &&
		type(report.version) == 'int' && report.version >= 0 &&
		type(report.local_version) == 'int' && report.local_version > 0 &&
		tx?.kind == 'release' && tx.mesh_enabled === false && tx.status == 'committed' &&
		token(tx.id) && token(tx.request_id) &&
		(tx.cause != 'controller_lost' || loss_receipt(report));
}
export function restoration_epoch(report) {
	let tx=report?.transaction;
	return {confirmed:restored(report),request_id:tx?.request_id ?? null,transaction_id:tx?.id ?? null,
		kind:tx?.kind ?? null,mesh_enabled:tx?.mesh_enabled ?? null,status:tx?.status ?? null};
}

// Only a matching Root-authorized close operation may create this durable fact.
// Neither a paused bit nor the current authorized bit is restoration evidence.
export function record_restoration(state, root, member, report) {
	if (member.authorized !== true || !restored(report)) return null;
	let scope=binding(root,member), ack=report.command, manual=member.mesh_mode,
		job=state.lifecycle, node=job?.nodes?.[member.id];
	if (scope && loss_receipt(report) && report.version<=state.version &&
		report.local_version>=(member.report?.local_version || 0))
		return {schema:1,binding:scope,request_id:report.transaction.request_id,transaction_id:report.transaction.id,
			version:report.version,local_version:report.local_version};
	if (!scope || ack?.mesh !== true || ack.status != 'committed' || ack.health_confirmed !== true ||
		ack.transaction_id != report.transaction.id || ack.transaction != report.transaction.request_id ||
		ack.version !== report.version) return null;
	let approved_manual=manual?.enabled === false && manual.id == ack.transaction &&
		manual.version == report.version && ack.id == 'local-mesh-' + manual.id &&
		manual.status == 'committed';
	let approved_remote=job?.enabled === false && job.node_id == member.id && job.id == ack.transaction && node &&
		index([job.id + '-mesh_confirm',job.id + '-mesh_apply',job.id + '-mesh_rollback'],ack.id) >= 0 &&
		index(['disabled','committed'],node.status)>=0;
	if (!approved_manual && !approved_remote) return null;
	return {schema:1,binding:scope,request_id:ack.transaction,transaction_id:report.transaction.id,
		version:report.version,local_version:report.local_version};
}

export function restoration_pending(state, member) {
	for (let job in [member?.mesh_mode,member?.repair])
		if (job && (job.command != null || index(FINAL,job.status) < 0)) return true;
	for (let job in [state?.active,state?.lifecycle]) {
		let node=job?.nodes?.[member?.id];
		if (node && (node.command != null || index(COORDINATED_FINAL,job.phase) < 0 &&
			!(job.enabled === false && node.status == 'disabled'))) return true;
	}
	return false;
}

export function restored_member(state, root, member) {
	let receipt=member?.mesh_restore_receipt, scope=binding(root,member), report=member?.report;
	if (!scope || type(receipt) != 'object' || length(keys(receipt)) != 6 ||
		receipt.schema !== 1 || !equal(receipt.binding,scope) || member.mesh_paused !== true ||
		!restored(report) || restoration_pending(state,member)) return false;
	return receipt.request_id == report.transaction.request_id && receipt.transaction_id == report.transaction.id &&
		receipt.version === report.version && member.version === report.version && receipt.local_version === report.local_version;
}

// The short-lived report observation is separate from path/poll liveness.
export function fresh_restoration(io, root, member) {
	let report=io.restoration_observation?.(member.id,member.report,
		{controller_id:root.id,network_id:root.network_id,certificate:member.certificate});
	let now=io.now();
	return report?.boot == io.boot() && index(['int','double'],type(report.seen)) >= 0 &&
		index(['int','double'],type(now)) >= 0 && report.seen <= now && now - report.seen < 15 &&
		report.confirmed === true;
}

// Root restoration intentionally removes its AP control paths. Freeze the
// already fresh structural proof before that removal, excluding live counters.
export function shutdown_guard(state, root, job) {
	let members={};
	for(let id in keys(state.members || {})) {
		let m=state.members[id],r=m.report;
		members[id]={id:m.id,authorized:m.authorized ?? null,certificate:m.certificate ?? null,
			control:m.control ?? null,control_protocol:m.control_protocol ?? null,
			mesh_paused:m.mesh_paused ?? null,version:m.version ?? null,
			receipt:m.mesh_restore_receipt ?? null,mesh_mode:m.mesh_mode ?? null,repair:m.repair ?? null,
			pending:restoration_pending(state,m),report:{configured:r?.configured ?? null,
				mesh_enabled:r?.mesh_enabled ?? null,version:r?.version ?? null,local_version:r?.local_version ?? null,
				drift:r?.drift ?? null,restoration:restoration_epoch(r)}};
	}
	return sha256(sprintf('%J',canonical({kind:'root_shutdown',controller:{id:root.id,role:root.role,
		network_id:root.network_id,fingerprint:root.fingerprint ?? null},version:state.version,
		intent:state.intent,job:{id:job.id,boot:job.boot,enabled:job.enabled,deadline:job.deadline,
			created:job.created,node_id:job.node_id ?? null,
			transaction_id:job.root.transaction_id},members})));
}
