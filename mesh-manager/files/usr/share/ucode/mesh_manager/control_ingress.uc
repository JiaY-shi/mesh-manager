// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { loss_receipt } from './controller_loss.uc';
import { restored_member } from './restoration.uc';

// destination comes from getsockname() in the native TLS listener, never JSON.
export function control_ingress(root, state, id, request, destination, boot, now) {
	let member=state?.members?.[id], action=request?.action;
	if (root?.role!='root' || type(destination)!='string' ||
		index([root.address,'169.254.254.1'],destination)<0)
		die('invalid_transport: Controller listener identity is unavailable');
	if (member?.authorized!==true) {
		if (member?.authorized===false && type(member.removed)=='int' &&
			request?.protocol===1 && request.network_id==root.network_id && action=='poll' &&
			restored_member(state,root,member)) return {revoked:true};
		die('not_authorized: Node identity is not authorized');
	}
	if (type(request)!='object' || request.protocol!==1 || request.network_id!=root.network_id ||
		index(['poll','probe','repair_intent','repair_reserve','repair_abort','repair_check',
			'mesh_intent','mesh_reserve','mesh_abort','mesh_check','handoff_check','standby_hint'],action)<0)
		die('invalid_request: Invalid node protocol');
	if (destination=='169.254.254.1') return {pin:true};
	// Read-only, signed Root BSSIDs disclose no intent or credentials and never
	// count as a health/restoration receipt. Legacy paused APs can learn the pin.
	if(action=='standby_hint')return {};
	if (action=='handoff_check')
		die('control_required: First configuration confirmation requires the isolated controller connection');
	// The probe has no configuration payload. Its native fast path is separately authenticated.
	if (action=='probe' || action=='mesh_abort') return {};
	if (index(['mesh_intent','mesh_reserve'],action)>=0 && request.enabled===false)
		return {exit_intent:true};
	let assigned=index(keys(member),'control')>=0 || state.control_schema===1,
		required=index(keys(member),'control_bound')>=0 || assigned &&
			(member.version>0 || member.report?.configured===true);
	// A first candidate may briefly reach the isolated listener, then roll
	// back to its original LAN/WAN. Keep the pin, but accept only its exact
	// recovery receipt and another current catchup, never a repair or batch.
	// A journal lock may interrupt apply after staging. Only the exact current
	// Root-issued first candidate can reconnect to retry that guarded apply.
	let report=request.report, tx=report?.transaction, ack=report?.command,
		previous=member.report, prior=previous?.transaction, issued=member.first_configuration;
	// A local recovery policy is deliberately independent of a Root job. This
	// terminal receipt is authenticated, cannot deliver a configuration command,
	// and must advance or match the known AP journal, never downgrade it.
	if (action=='poll' && loss_receipt(report) && report.configured===true && report.mesh_enabled===false &&
		type(report.drift)=='array' && !length(report.drift) && report.local_version>=(previous?.local_version || 0) &&
		type(report.version)=='int' && report.version>=0 && report.version<=state.version &&
		tx.kind=='release' && tx.mesh_enabled===false && tx.status=='committed') {
		let job=state.lifecycle;
		if (member.mesh_paused===true && member.mesh_restore_receipt?.transaction_id==tx.id &&
			job?.enabled===true && job.node_id==id && job.boot==boot && job.deadline>now &&
			index(['preparing','ready','applying'],job.phase)>=0) return {recovery_enable:job.id};
		return {receipt_only:true};
	}
	if (!required || member.mesh_paused===true) {
		if (action=='poll' || index(['mesh_intent','mesh_reserve'],action)>=0 && request.enabled===true)
			return {bootstrap:true};
	}
	if (action=='poll' && member.control_configured!==true && member.version===0 &&
		previous?.local_version===0 && previous.configured===false && previous.version===0 && previous.mesh_enabled===false &&
		report?.local_version===0 && report.configured===false && report.version===0 &&
		report.mesh_enabled===false && type(report.drift)=='array' && !length(report.drift) &&
		tx?.kind=='configure' && tx.mesh_enabled==null && type(tx.id)=='string' && length(tx.id)>=16 &&
		ack?.transaction_id==tx.id && ack.status==tx.status && ack.mesh===false && ack.repair===false &&
		type(ack.conflicts)=='array' && !length(ack.conflicts) &&
		index(['staged','rolled_back','expired'],tx.status)>=0 &&
		type(ack.version)=='int' && ack.version>0 && ack.version<=state.version &&
		(tx.status!='staged' || ack.version===state.version) &&
		ack.id=='catchup-'+sprintf('%016d',ack.version) && ack.transaction==ack.id &&
		type(tx.request_id)=='string' && length(tx.request_id)<=96 && index(tx.request_id,'mesh-'+ack.id)==0 &&
		// Older Roots already persisted the first isolated receipt. Its exact
		// transaction is sufficient to recover without rewriting the journal.
		(tx.status!='staged' && prior?.id==tx.id && prior.request_id==tx.request_id && prior.kind=='configure' &&
			prior.mesh_enabled==null && previous.command?.id==ack.id &&
			previous.command.transaction_id==tx.id && previous.command.version==ack.version &&
			previous.command.mesh===false && previous.command.repair===false &&
			index(['applying','awaiting_confirm','rolled_back','expired'],prior.status)>=0 ||
		 issued?.id==ack.id && issued.version==ack.version && issued.request_id==tx.request_id))
		return {initial_recovery:true};
	function current(job) {
		return job?.boot==boot && index(['int','double'],type(job.deadline))>=0 &&
			index(['int','double'],type(now))>=0 && now>=0 && now<job.deadline;
	}
	let manual=member.mesh_mode, managed=state.lifecycle, operation=null, job=null;
	if (manual?.enabled===false) job=manual;
	if (managed?.enabled===false && managed.nodes?.[id] &&
		(request.report?.command?.transaction==managed.id || !job)) job=managed;
	operation=job?.id;
	if (type(operation)=='string' && length(operation)>=16 && length(operation)<=64) {
		if (current(job) && action=='mesh_check' && manual?.id==operation && request.request_id==operation &&
			request.version==manual.version) return {restoring:operation};
		let report=request.report, command=report?.command, tx=report?.transaction;
		if (action=='poll' && command?.mesh===true && command.transaction==operation &&
			command.transaction_id==tx?.id && type(tx?.id)=='string' && length(tx.id)>0 &&
			tx.kind=='release' && tx.mesh_enabled===false && command.status==tx.status &&
			index(['applying','awaiting_confirm','committed','rollback_requested','rolling_back',
				'rolled_back','rollback_conflict'],tx.status)>=0) {
			if (current(job)) return {restoring:operation};
			else if (index(['committed','rolled_back','rollback_conflict'],tx.status)>=0)
				// A restart/expired coordinator may still receive the final result of
				// its durable authorization. Never deliver another command in reply.
				return {restoring:operation,receipt_only:true};
		}
	}
	die('control_required: Use the isolated controller connection for this request');
}

// A recovery receipt must not accidentally deliver a different queued change
// over LAN. Its existing Mesh restore command is the only permitted downlink.
export function ingress_response(access, reply) {
	if (access.exit_intent) return {...reply,intent:null};
	if (access.receipt_only) return {...reply,command:null};
	let command=reply.command;
	if (access.recovery_enable && command && (command.transaction!=access.recovery_enable ||
		command.mesh_enabled!==true || index(['mesh_prepare','mesh_apply','mesh_confirm'],command.action)<0))
		return {...reply,command:null};
	if (access.initial_recovery && command && (command.action!='catchup' || command.version!=reply.version ||
		command.id!='catchup-'+sprintf('%016d',reply.version))) return {...reply,command:null};
	if (access.restoring && command && (command.transaction!=access.restoring ||
		command.mesh_enabled!==false || command.intent!=null ||
		index(['mesh_prepare','mesh_apply','mesh_confirm','mesh_rollback'],command.action)<0))
		return {...reply,command:null};
	return reply;
}
