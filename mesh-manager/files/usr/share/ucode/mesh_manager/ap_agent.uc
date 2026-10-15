// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import * as crypto from 'mesh_crypto';
import * as durable from './durable.uc';
import * as client_events from './client_events.uc';
import { same_ap_binding } from './identity.uc';
import { effective_settings } from './local_settings.uc';
import { require_lease } from './control_lease.uc';
import { local_intent, node_peers, mesh_mac } from './extended.uc';
import { clone, equal } from './model.uc';
import { handoff_state } from './first_handoff.uc';
import { handoff_context, handoff_poll_context, handoff_poll } from './handoff_runtime.uc';
import { snapshot, first_handoff_locked, read_locked, departure_locked } from './runtime.uc';
import { onboard_stop, onboard_capture, onboarding_transport, onboard_standby_start,
	onboard_standby_stop, onboard_pending } from './onboarding.uc';
import { peer_router, isolated_control_required } from './protocol_worker.uc';
import { exchange, probe, probe_control } from './peer_transport.uc';
import { departure_service } from './departure.uc';
import { standby_bootstrap } from './standby.uc';
import { agent_local } from './agent_local.uc';
import { sanitize_report } from './agent_report.uc';
import {migration_receipt} from './migration_model.uc';
import {accept_anchor_roster} from './anchor_roster.uc';
import {certificate_renewal} from './certificate_renewal.uc';
import {config_signing} from './config_signing.uc';
const certificates=certificate_renewal(durable);
const signing=config_signing(durable);

// Only AP behavior lives here. Root orchestration is loaded in another worker.
// A long-lived AP retains the original bounded retry windows across ticks.
let catchup_deferred = null;
let standby_deferred = null;
let migration_client;
function migration() {
	if (!migration_client) migration_client=require('mesh_manager.migration_client_worker')({
		durable,local:agent_local,exchange,effective_settings,local_intent,mesh_mac
	});
	return migration_client;
}

function error_code(e) {
	return match(e.message || '', /^([a-z_]{1,32}): /)?.[1] || 'internal_error';
}
function io() { return { ...durable, local: agent_local() }; }
const routed_exchange = peer_router({ now: durable.now,
	available: (device) => fs.access('/sys/class/net/' + device), probe, exchange });
export function agent_exchange(binding, request, context) {
	let state=durable.load('state.json'),transport=state?.paused===true ? onboarding_transport(binding.address) : null;
	if(transport)return exchange(binding,{...request,control_schema:1},false,transport.device);
	return routed_exchange(binding, { ...request, control_schema: 1 }, {
		...context, control_required: isolated_control_required(state, request)
	});
}

function candidate(data, command, i) {
	let local = { ...effective_settings(data, i.load('state.json')), peers:
		node_peers(data.id,command) };
	return local_intent(command.intent, local, false, 'bridge', data.id, command.control ? require_lease(command.control) : null,data.anchor || command.anchor);
}
export function node_command(data, command, i, observed, handoff) {
	let job = data.agent;
	if (data.handoff != null && (command.action != 'catchup' || job?.id != null && job.id != command.id))
		die('busy: The original first configuration must be confirmed before another controller transaction');
	// First handoff retains its exact approved identity until commitment. A
	// later signed lifecycle command supplies the pin before restoring Wi-Fi.
	if(command.bootstrap!=null && data.handoff==null)data.bootstrap=standby_bootstrap(command.bootstrap);
	let local_state = observed;
	function status() {
		if (local_state == null) local_state = i.local.status?.();
		return local_state;
	}
	if (match(command.action || '', /^mesh_/)) {
		if (command.action == 'mesh_prepare') {
			if (job?.id == command.id && index(['ready','disabled','enabled','error'], job.status) >= 0) return;
			let local = status();
			if (local.active && index(['committed','rolled_back','rollback_conflict','expired'], local.active.status) < 0)
				die('busy: Another transaction is active');
			let enabled = command.mesh_enabled === true,
				verify_restore = !enabled && local.mesh_enabled === false &&
					!(local.active?.kind == 'release' && local.active.status == 'committed'),
				plan = local.mesh_enabled === enabled && !verify_restore ? null :
					i.local.mesh_preview(enabled, enabled ? candidate(data, command, i) : null);
			data.agent = { id: command.id, transaction: command.transaction, mesh: true,
				version: command.version, plan, status: !plan ? enabled ? 'enabled' : 'disabled' : length(plan.errors) ? 'error' : 'ready',
				error: plan && length(plan.errors) ? plan.errors[0].code : null };
		} else if (command.action == 'mesh_apply') {
			if (job?.id == command.id) {
				if (job.transaction_id && job.status == 'staged') {
					if (command.mesh_enabled !== true) i.local.authorize_restoration?.(job.transaction_id,command.transaction);
					i.local.apply(job.transaction_id); job.status = 'apply_requested'; i.save('identity.json', data);
				}
				return;
			}
			let enabled = command.mesh_enabled === true, intent = enabled ? candidate(data, command, i) : null;
			let staged = i.local.mesh_stage(enabled, intent, command.transaction, true, command.approval);
			data.agent = { id: command.id, transaction: command.transaction, version: command.version,
				mesh: true, status: 'staged', transaction_id: staged.id, mode: intent?.backhaul?.mode || null };
			i.save('identity.json', data);
			if (!enabled) i.local.authorize_restoration?.(staged.id,command.transaction);
			i.local.apply(staged.id); data.agent.status = 'apply_requested';
		} else if (command.action == 'mesh_confirm') {
			if (!job?.mesh || job.transaction != command.transaction || !job.transaction_id)
				die('invalid_state: Mesh confirmation does not match the AP transaction');
			i.local.confirm(job.transaction_id); job.id = command.id; job.status = 'committed'; job.health_confirmed=true;
			data.cluster_version = command.version;
		} else if (command.action == 'mesh_rollback') {
			if (job?.mesh && job.transaction == command.transaction && job.transaction_id) {
				let local=status(),a=local?.active;
				if (command.mesh_enabled===false && local.mesh_enabled===false && a?.id==job.transaction_id &&
					a.request_id==job.transaction && a.kind=='release' && a.status=='committed' &&
					i.local.restoration_committed?.(a.id,a.request_id)) {
					// A coordinator may expire while the AP finishes its approved
					// local restore. Report that result; a committed journal cannot
					// be turned back into an unconfirmed rollback.
					job.id=command.id;job.status='committed';job.health_confirmed=true;
					data.cluster_version=job.version;
				} else {
					let result = i.local.rollback(job.transaction_id); job.id = command.id; job.status = result.status;
				}
			} else data.agent = { id: command.id, transaction: command.transaction, mesh: true,
				version: command.version, status: 'no_change' };
		} else die('invalid_method: Invalid Mesh controller command');
		i.save('identity.json', data); return;
	}
	local_state = status();
	if (local_state?.mesh_enabled === false && local_state.configured === true) {
		let repair_cleanup = command.action == 'repair_rollback';
		if (!repair_cleanup && command.action != 'rollback')
			die('mesh_disabled: Disabled AP does not accept configuration synchronization');
		// A delayed cancellation must not follow stale IDs into the completed disable or a new enable.
		let active = local_state.active;
		if (!job?.transaction_id || job.transaction != command.transaction ||
			active?.id != job.transaction_id || active.mesh_enabled != null ||
			active.kind != (repair_cleanup ? 'repair' : 'configure') ||
			(repair_cleanup ? job.repair !== true : job.repair === true || job.mesh === true)) {
			if (active && index(['committed', 'rolled_back', 'rollback_conflict', 'expired'], active.status) < 0)
				die('busy: Another local transaction is pending before cleanup');
			let ack = { id: command.id, transaction: command.transaction, version: command.version,
				repair: repair_cleanup, status: 'no_change' };
			if (!equal(job, ack)) { data.agent = ack; i.save('identity.json', data); }
			return;
		}
	}
	if (command.action == 'repair_prepare') {
		if (job?.id == command.id && index(['ready', 'error'], job.status) >= 0) return;
		let local = status();
		if (local.active && index(['committed', 'rolled_back', 'rollback_conflict', 'expired'], local.active.status) < 0)
			die('busy: Another transaction is active');
		let plan = i.local.repair_preview(candidate(data, command, i));
		data.agent = { id: command.id, transaction: command.transaction, version: command.version,
			repair: true, status: length(plan.errors) ? 'error' : 'ready',
			error: length(plan.errors) ? 'preflight_failed' : null, plan };
	} else if (command.action == 'repair_apply') {
		if (job?.id == command.id) {
			if (job.transaction_id && job.status == 'staged') {
				i.local.apply(job.transaction_id); job.status = 'apply_requested'; i.save('identity.json', data);
			}
			return;
		}
		let intent = candidate(data, command, i);
		let staged = i.local.repair_stage(intent, 'repair-' + command.transaction, true, command.approval);
		data.agent = { id: command.id, transaction: command.transaction, version: command.version,
			repair: true, status: 'staged', mode: intent.backhaul.mode, transaction_id: staged.id };
		i.save('identity.json', data);
		i.local.apply(staged.id); data.agent.status = 'apply_requested';
	} else if (command.action == 'repair_confirm') {
		if (!job?.repair || job.transaction != command.transaction || job.version != command.version || !job.transaction_id)
			die('invalid_state: Repair confirmation does not match the node transaction');
		i.local.confirm(job.transaction_id); job.id = command.id; job.status = 'committed';
		data.cluster_version = command.version;
	} else if (command.action == 'repair_rollback') {
		if (job?.repair && job.transaction == command.transaction && job.transaction_id) {
			let result = i.local.rollback(job.transaction_id);
			job.id = command.id; job.status = result.status;
		} else data.agent = { id: command.id, transaction: command.transaction, version: command.version,
			repair: true, status: 'no_change' };
	} else if (command.action == 'prepare') {
		if (job?.id == command.id && index(['ready', 'error'], job.status) >= 0 && job.error != 'busy') return;
		let plan = i.local.preview(candidate(data, command, i));
		data.agent = {
			id: command.id,
			transaction: command.transaction,
			version: command.version,
			status: length(plan.errors) ? 'error' : 'ready',
			error: length(plan.errors) ? 'preflight_failed' : null,
			plan
		};
	} else if (command.action == 'apply' || command.action == 'catchup') {
		let retry_request = null;
		if (job?.id == command.id) {
			if (job.transaction_id && job.status == 'staged') {
				i.local.apply(job.transaction_id); job.status = 'apply_requested'; i.save('identity.json', data);
				return;
			}
			// A catchup is the current authenticated intent, not a one-shot batch
			// approval. Retry only its exact completed, conflict-free recovery.
			// The first wireless handoff retains its separately sealed lineage.
			let active = status()?.active;
			let rejected_preview=command.action=='catchup' && data.handoff==null && job.catchup===true &&
				job.version==command.version && job.status=='error' && !job.transaction_id;
			if (!rejected_preview && (command.action != 'catchup' || data.handoff != null || job.catchup !== true ||
				job.version != command.version || active?.id != job.transaction_id ||
				active.kind != 'configure' || active.mesh_enabled != null ||
				index(['rolled_back', 'expired'], active.status) < 0 ||
				index(['rolled_back', 'expired'], job.status) < 0 || length(active.conflicts || []))) return;
			if (!rejected_preview) {
				let boot = i.boot(), now = i.now();
				if (job.retry?.boot != boot || type(job.retry?.next) != 'int' && type(job.retry?.next) != 'double') {
					job.retry = { boot, next: now + 30 }; i.save('identity.json', data); return;
				}
				if (now < job.retry.next) return;
				retry_request = 'mesh-' + command.id + '-' + substr(crypto.sha256(job.transaction_id), 0, 16);
			}
		}
		let retry_key=command.action=='catchup' && data.handoff==null ?
			sprintf('%J',[data.id,command.id,command.version,job?.transaction_id || null]) : null;
		let retry_clock=retry_key && i.now && i.boot ? {now:i.now(),boot:i.boot()} : null;
		if (retry_clock && catchup_deferred?.key==retry_key && catchup_deferred.boot==retry_clock.boot &&
			retry_clock.now>=catchup_deferred.observed && retry_clock.now<catchup_deferred.next) return;
		let intent = candidate(data, command, i),
			plan = i.local.preview(intent);
		if (retry_key && length(plan.errors)) {
			let code=index(['wireless_control_incompatible','wireless_probe_unavailable','missing_mesh','missing_mesh_acl'],
				plan.errors[0]?.code)>=0 ? plan.errors[0].code : 'preflight_failed';
			if (retry_clock) {
				let failures=catchup_deferred?.key==retry_key && catchup_deferred.boot==retry_clock.boot ?
					min(4,catchup_deferred.failures+1) : 1;
				catchup_deferred={key:retry_key,boot:retry_clock.boot,observed:retry_clock.now,failures,
					next:retry_clock.now+(code=='wireless_control_incompatible' ? 300 : [30,60,120,300][failures-1])};
			}
			// Keep the exact rolled-back receipt used by the isolated ingress
			// recovery check. A failed preview never creates a new transaction.
			let rejected=retry_request ? {...job,retry_error:code,error:code} : {
				id:command.id,transaction:command.transaction || command.id,version:command.version,
				catchup:true,status:'error',error:code};
			if (!equal(data.agent,rejected)) {data.agent=rejected;i.save('identity.json',data);}
			return;
		}
		if (retry_key) catchup_deferred=null;
		let approval = command.action == 'catchup' ? plan : command.approval;
		let stage = data.handoff != null && command.action == 'catchup'
			? (...args) => {
				if (!handoff?.frame || !handoff.proof)
					die('handoff_conflict: First catchup has no original signed context');
				return i.local.first_handoff_stage(...args, handoff.frame, handoff.proof);
			} : i.local.stage;
		let staged = stage(
			intent,
			retry_request || 'mesh-' + (command.transaction || command.id),
			true,
			approval
		);
		data.agent = {
			id: command.id,
			transaction: command.transaction || command.id,
			version: command.version,
			mode: command.intent.backhaul.mode,
			status: 'staged',
			transaction_id: staged.id,
			catchup: command.action == 'catchup'
		};
		i.save('identity.json', data);
		i.local.apply(staged.id);
		data.agent.status = 'apply_requested';
	} else if (command.action == 'confirm') {
		if (job?.id == command.id && job.status == 'committed') return;
		if (
			!job ||
			job.transaction != command.transaction ||
			job.version != command.version ||
			!job.transaction_id
		)
			die('invalid_state: Confirmation does not match active node transaction');
		i.local.confirm(job.transaction_id);
		job.id = command.id;
		job.status = 'committed';
		data.cluster_version = command.version;
	} else if (command.action == 'rollback') {
		if (
			job?.id == command.id &&
			index(['rolled_back', 'rollback_conflict', 'no_change'], job.status) >= 0
		)
			return;
		if (job?.transaction == command.transaction && job.transaction_id) {
			i.local.rollback(job.transaction_id);
			job.id = command.id;
			job.status = 'rollback_requested';
		} else data.agent = { id: command.id, transaction: command.transaction, status: 'no_change' };
	} else die('invalid_method: Invalid controller command');
	i.save('identity.json', data);
}
export function command_error(command, e, previous, current) {
	// A previously healthy sample may settle differently at native confirmation.
	// Keep only the exact signed batch pending; its original watchdog/deadline
	// and fresh native health/CAS checks remain authoritative on every retry.
	let active = current?.active;
	if (error_code(e) == 'unhealthy' && command.action == 'confirm' &&
		previous?.status == 'awaiting_confirm' && previous.repair !== true &&
		previous.mesh !== true && previous.catchup !== true &&
		type(previous.transaction) == 'string' && previous.transaction === command.transaction &&
		type(previous.version) == 'int' && previous.version >= 1 && previous.version === command.version &&
		type(previous.transaction_id) == 'string' && length(previous.transaction_id) &&
		active?.id === previous.transaction_id && active.request_id === previous.transaction &&
		active.kind == 'configure' && active.mesh_enabled === null && active.status == 'awaiting_confirm' &&
		type(active.remaining) == 'int' && active.remaining > 0) return null;
	return {
		id: command.id,
		transaction: command.transaction,
		version: command.version,
		repair: match(command.action || '', /^repair_/) != null,
		mesh: match(command.action || '', /^mesh_/) != null,
		status: 'error',
		error: error_code(e)
	};
}
// The journal commits before its derived identity receipt. Only the sealed
// original first catchup may recover that receipt without another Root command.
// The caller already owns the cluster lock; one local lock fences recovery.
function recover_first_catchup(data) {
	return first_handoff_locked(() => {
		let original = handoff_context();
		if (original.scope.identity !== sprintf('%J', data) ||
			handoff_state(original.scope, original.journal, original.snapshot, original.boot, original.now).stage != 'committed')
			die('handoff_conflict: Original first commit receipt is unavailable');
		let current = json(original.scope.identity), journal = json(original.journal), job = current.agent,
			candidate = clone(current), deadline = original.now + 5000;
		if (job?.catchup !== true || job.transaction_id !== journal.active?.id ||
			job.id !== journal.first_handoff?.root_id || job.version !== journal.first_handoff?.root_version)
			die('handoff_conflict: Original first catchup receipt changed');
		candidate.agent.status = 'committed';
		candidate.agent.conflicts = clone(journal.active.conflicts);
		candidate.cluster_version = job.version;
		let fresh = handoff_context();
		if (!equal(fresh.scope, original.scope) || fresh.journal !== original.journal || fresh.snapshot !== original.snapshot ||
			fresh.boot !== original.boot || !equal(fresh.transport, original.transport) || type(fresh.now) != 'int' ||
			fresh.now < original.now || fresh.now >= deadline)
			die('handoff_conflict: First commit receipt scope changed');
		let expected = sprintf('%J', candidate);
		durable.write_cas('identity.json', original.scope.identity, expected, min(5000, deadline - fresh.now));
		let after = handoff_context();
		if (!equal(after.scope, { ...original.scope, identity: expected }) || after.journal !== original.journal ||
			after.snapshot !== original.snapshot || after.boot !== original.boot || !equal(after.transport, original.transport) ||
			type(after.now) != 'int' || after.now < fresh.now || after.now >= deadline)
			die('handoff_conflict: First commit receipt publication changed or arrived too late');
		data.agent = candidate.agent; data.cluster_version = candidate.cluster_version;
	});
}
export function update_agent_job(data, status, i) {
	let job = data.agent;
	if (!job?.transaction_id || status.active?.id != job.transaction_id) return;
	let state = status.active.status;
	// Root's signed mesh_apply was approved and staged before its temporary
	// control transport was retired. Continue that exact request locally if
	// teardown or the recovery heartbeat interrupted the first apply call.
	// A locally staged UI candidate has a different ID and remains unapplied.
	if (job.mesh === true && job.id === job.transaction + '-mesh_apply' &&
		state == 'staged' && status.active.kind == 'configure' && status.active.mesh_enabled === true &&
		status.active.request_id === job.transaction &&
		(job.status == 'staged' || job.status == 'error' &&
			index(['busy','cleanup_conflict','daemon_unavailable'],job.error) >= 0)) {
		i.local.apply(job.transaction_id); job.status = 'apply_requested';
		delete job.error; i.save('identity.json',data); return;
	}
	if (data.handoff != null && job.catchup === true && state == 'committed' &&
		status.active.kind == 'configure' && status.active.mesh_enabled == null &&
		(job.status != state || data.cluster_version !== job.version)) {
		recover_first_catchup(data); return;
	}
	// Confirmation commits the journal before the derived identity receipt.
	// Recover only the exact successful close, including its Root version.
	let restored = state == 'committed' && job.mesh === true &&
		status.active.kind == 'release' && status.active.mesh_enabled === false &&
		status.active.request_id == job.transaction && type(job.version) == 'int' && job.version >= 1;
	if (
		index(
			['awaiting_confirm', 'committed', 'rolled_back', 'rollback_conflict', 'expired'],
			state
		) >= 0 &&
		(job.status != state || restored &&
			(job.health_confirmed !== true || data.cluster_version !== job.version))
	) {
		job.status = state;
		if (restored) { job.health_confirmed=true; data.cluster_version=job.version; }
		job.conflicts = status.active.conflicts || [];
		if (state == 'committed' && job.repair) data.cluster_version = job.version;
		if (index(['rolled_back', 'rollback_conflict', 'expired'], state) >= 0)
			job.error = 'local_recovery';
		if (job.catchup === true && data.handoff == null && index(['rolled_back', 'expired'], state) >= 0 &&
			!length(job.conflicts) && i.boot && i.now)
			job.retry = { boot: i.boot(), next: i.now() + 30 };
		i.save('identity.json', data);
	}
}
export function ap_agent_tick() {
	let data = durable.load('identity.json');
	if (!data) return;
	function depart(receipt) {
		return durable.locked(()=>departure_locked(local=>departure_service({...local,
			read:durable.read,replace:(name,before,after)=>durable.write_cas(name,before,after,5000),
			with_local:callback=>callback()}).resume(receipt)),5);
	}
	if (data.departing) { onboard_standby_stop(); depart(); return; }
	if (data.role != 'ap' || !data.binding) return;
	if(data.migration && index(['complete','cancelled','expired'],data.migration.phase)<0) {
		migration().tick();data=durable.load('identity.json');
	}
	let i = io(),
		status = i.local.agent_status();
	data = durable.locked(() => {
		let current = durable.load('identity.json');
		if (!same_ap_binding(data, current))
			die('identity_error: AP binding changed');
		update_agent_job(current, status, i); return current;
	});
	try {
		if (status.mesh_enabled && status.local.clients_complete)
			client_events.observe(data.id, status.local.clients);
	} catch (e) {}
	let backhaul = { active: status.intent?.backhaul?.mode == 'wired' ? 'wired' : 'unknown' };
	if (status.active?.kind != 'release' && (data.agent?.mode || status.intent?.backhaul?.mode) != 'wired' &&
		data.agent?.status == 'awaiting_confirm') {
		for (let path in [['mm-cw', 'wired_verified'], ['mm-cm', 'wireless_verified']]) {
			try {
				backhaul[path[1]] = probe_control(data.binding, path[0]);
			} catch (e) {
				backhaul[path[1]] = false;
			}
		}
	}
	let observed;
	try { observed = json(fs.readfile('/var/run/mesh-manager-backhaul.json') || 'null'); }
	catch (e) { observed = null; }
	if (observed?.boot == durable.boot() && type(observed.observed) == 'int' &&
		time() - observed.observed >= 0 && time() - observed.observed < 15 &&
		index(['wired', 'wireless', 'none','gateway'], observed.active) >= 0)
		backhaul = { ...backhaul, active: observed.active, carrier: observed.carrier,
			wired: observed.wired, wireless: observed.wireless,
			quality: status.local.backhaul?.quality || null };
	let report = sanitize_report({
		version: data.cluster_version || 0,
		local_version: status.version,
		mesh_enabled: status.mesh_enabled,
		configured: status.configured,
		model: status.local.board?.model,
		software: status.local.software,
		management: status.local.management,
		drift: status.drift,
		health: status.health,
		backhaul,
		data_gateway:status.intent?.controller===true && data.anchor?.id==data.id,
		clients: status.mesh_enabled ? status.local.clients : [],
		clients_complete: status.mesh_enabled && status.local.clients_complete,
		command: data.agent,
		migration:migration_receipt(data.migration),
		controller_recovery: status.controller_recovery,
		transaction: status.active ? { id: status.active.id, request_id:status.active.request_id, kind: status.active.kind,
			mesh_enabled: status.active.mesh_enabled, status: status.active.status,
			...(status.active.cause=='controller_lost' ? {cause:'controller_lost'} : {}),
			...(status.active.restore_recheck === true ? {restore_recheck:true} : {}) } : null
	});
	let request = { protocol: 1, network_id: data.binding.network_id, action: 'poll', report },
		handoff = data.handoff != null ? { frame: handoff_poll_context(), proof: null } : null;
	if(!handoff)request.credentials=certificates.poll(data);
	if(!handoff)request.signing_epoch=data.signing?.epoch || 0;
	let reply;
	try {reply=handoff?.frame ? handoff_poll(data.binding,request,handoff.frame,value=>{handoff.proof=value;}) : agent_exchange(data.binding,request,data);}
	catch(e) {
		let state=durable.load('state.json');
		if(index(e.message || '', 'peer_unavailable:')==0 && state?.paused===true && !onboard_pending()) {
			let epoch=crypto.sha256(sprintf('%J',[data.binding,state.active?.id])), now=durable.now();
			if(standby_deferred?.epoch==epoch && now<standby_deferred.next)die(e.message);
			let scope=durable.locked(()=>read_locked(()=>({...onboard_capture().scope,
				state:durable.read('state.json'),snapshot:sprintf('%J',snapshot()),cluster:durable.read('cluster.json')}),5),5);
			try {
				onboard_standby_start(scope,()=>durable.locked(()=>read_locked(()=>({...onboard_capture().scope,
					state:durable.read('state.json'),snapshot:sprintf('%J',snapshot()),cluster:durable.read('cluster.json')}),5),5));
				standby_deferred=null;
			}catch(start_error){
				let attempts=standby_deferred?.epoch==epoch ? min(standby_deferred.attempts+1,4) : 1;
				standby_deferred={epoch,attempts,next:durable.now()+[30,60,120,300][attempts-1]};
				die(start_error.message);
			}
			reply=agent_exchange(data.binding,request,data);
		}else die(e.message);
	}
	if (
		reply.controller_id != data.binding.controller_id ||
		reply.network_id != data.binding.network_id
	)
		die('identity_error: Controller identity changed');
	if(reply.credentials!=null) {
		// The poll capture is no longer needed. Reclaim it before checking the
		// unchanged write reserve on devices with little free memory.
		status=null;report=null;request=null;gc('collect');
		durable.locked(()=>certificates.accept(data,reply.credentials));
		data=durable.load('identity.json');
	}
	if(reply.signer_pin!=null) {
		status=null;report=null;request=null;gc('collect');
		durable.locked(()=>signing.accept(data,reply.signer_pin));
	}
	if(reply.anchor_roster!=null)durable.locked(()=>{
		let current=durable.load('identity.json');
		if(!same_ap_binding(data,current))die('identity_error: Gateway binding changed before roster update');
		let cluster=durable.load('cluster.json');
		if(accept_anchor_roster(current,cluster,reply.anchor_roster))durable.save('cluster.json',cluster);
	});
	if (match(reply.command?.action || '',/^migration_/)) {
		// Migration samples fresh local state. Release the completed poll's
		// capture before lazy compilation and its independent resource gate.
		let command=reply.command;
		status=null;report=null;request=null;
		gc('collect');
		migration().command(command);return;
	}
	if (reply.authorization?.status=='revoked') { onboard_standby_stop(); depart(reply); return; }
	let catchup = data.agent?.catchup && data.agent.status == 'awaiting_confirm';
	if (!reply.command && !catchup) return;
	let current = i.local.status();
	durable.locked(() => {
		let current_identity = durable.load('identity.json');
		if (!same_ap_binding(data, current_identity))
			die('identity_error: AP binding changed');
		data = current_identity;
		if (data.agent?.catchup && data.agent.status == 'awaiting_confirm' &&
			current.active?.id == data.agent.transaction_id && current.health?.ok) {
			i.local.confirm(data.agent.transaction_id); data.agent.status = 'committed';
			data.cluster_version = data.agent.version; i.save('identity.json', data);
			// The handoff worker needs its signed managed receipt before retiring
			// the original actor and bootstrap credentials, outside this lock.
			if (data.handoff == null) onboard_stop();
		}
		if (!reply.command) return;
		try { node_command(data, reply.command, i, current, handoff); }
		catch (e) {
			if (error_code(e) == 'busy') return;
			let previous = data.agent;
			let failed = command_error(reply.command, e, previous, current);
			if (!failed) return;
			data.agent = failed;
			if ((data.agent.repair && previous?.repair || data.agent.mesh && previous?.mesh) &&
				previous.transaction == reply.command.transaction) data.agent.transaction_id = previous.transaction_id;
			i.save('identity.json', data);
		}
	});
}
