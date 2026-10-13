// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { history_used } from './history_retention.uc';
import { clone, equal } from './model.uc';
import { mesh_mac } from './extended.uc';
import { adopt_leases, lease_for } from './control_lease.uc';
import { record_restoration, restored_member, fresh_restoration, shutdown_guard } from './restoration.uc';

const TERMINAL = ['complete', 'failed', 'partial', 'cancelled', 'expired'];
const LOCAL_TERMINAL = ['committed', 'rolled_back', 'rollback_conflict', 'expired', 'no_change', 'error'];
export function lifecycle_busy(s) {
	return s.lifecycle && (index(TERMINAL, s.lifecycle.phase) < 0 ||
		length(filter(values(s.lifecycle.nodes), (n) => n.command != null))) ||
		length(filter(values(s.members), (m) => m.authorized && m.mesh_mode &&
			index(LOCAL_TERMINAL, m.mesh_mode.status) < 0)) > 0;
}
export function public_lifecycle(job, plans) {
	if (!job) return null;
	let result = { id: job.id, phase: job.phase, node_id: job.node_id || null, enabled: job.enabled === true,
		created: job.created, failure: job.failure || null,
		root: { status: job.root.status, plan: job.root.plan || null,
			transaction_id: job.root.transaction_id || null, error: job.root.error || null },
		nodes: map(keys(job.nodes), (id) => ({ id, status: job.nodes[id].status,
			plan: job.nodes[id].plan || null, error: job.nodes[id].error || null,
			conflicts: job.nodes[id].conflicts || [] })) };
	if (plans === false) {
		result.root.has_plan = result.root.plan != null;
		delete result.root.plan;
		for (let node in result.nodes) {
			node.has_plan = node.plan != null;
			delete node.plan;
		}
	}
	return result;
}
export function configuration_busy(s, io) {
	let a = s.active, local = io.local?.repair_status?.();
	return a && (index(['complete', 'partial', 'failed', 'rolled_back', 'expired'], a.phase) < 0 ||
		length(filter(values(a.nodes), (n) => n.command != null))) ||
		length(filter(values(s.members), (m) => m.authorized && m.repair &&
			index(['committed', 'failed', 'rolled_back', 'rollback_conflict', 'expired'], m.repair.status) < 0)) ||
		local && index(LOCAL_TERMINAL, local.status) < 0;
}
export function lifecycle_service(io, pairing) {
	let tick;
	function save(s) { io.save('cluster.json', s); }
	function validate(id) {
		if (!match(id || '', /^[a-zA-Z0-9_-]{16,64}$/)) die('invalid_request: Invalid Mesh operation ID');
	}
	function fresh(id) {
		let seen = io.presence?.(id);
		return seen?.boot == io.boot() && io.now() - (seen.seen || 0) < 15;
	}
	function command(job, node, action) {
		let s = pairing.state();
		node.command = { id: job.id + '-' + action, transaction: job.id, action,
			mesh_enabled: job.enabled === true, version: s.version,
			intent: job.enabled === true ? clone(s.intent) : null, root_mac: mesh_mac(pairing.root().id),
			control: job.enabled === true ? node.control : null, bootstrap:io.bootstrap_wifi?.() || [],
			approval: action == 'mesh_apply' ? node.plan : null };
	}
	function all_disabled(s, require_fresh) {
		let root=pairing.root();
		for (let m in values(s.members)) {
			if (type(m.authorized) != 'bool')
				die('ap_restore_unverified: Retained AP authorization and restoration state are unknown');
			if (m.mesh_paused !== true) die('ap_restore_required: Disable every managed AP before disabling Root');
			if (!restored_member(s,root,m))
				die('ap_restore_unverified: Every retained AP, including revoked identities, needs a confirmed restoration receipt');
			if (require_fresh !== false && m.authorized === true && (!fresh(m.id) || !fresh_restoration(io,root,m)))
				die('node_offline: Every authorized AP must freshly report its confirmed restoration');
		}
	}
	function finish(s, phase, failure) {
		let job = s.lifecycle;
		job.phase = phase; job.failure = failure || null;
		s.lifecycle_history ||= [];
		let entry = public_lifecycle(job);
		delete entry.root.plan;
		for (let node in entry.nodes) delete node.plan;
		push(s.lifecycle_history, { ...entry, timestamp: time() });
		if (length(s.lifecycle_history) > 32) shift(s.lifecycle_history);
		save(s);
	}
	function root_proof_unchanged(s, job) {
		return !job.node_id && job.enabled === false && type(job.shutdown_guard) == 'string' &&
			match(job.shutdown_guard,/^[0-9a-f]{64}$/) != null &&
			job.shutdown_guard == shutdown_guard(s,pairing.root(),job);
	}
	function recover_root_commit(s, job) {
		if (job.node_id || job.enabled !== false || !job.root.transaction_id ||
			index(['root_applying','awaiting_confirm'],job.phase) < 0) return false;
		let committed=io.local.restoration_committed?.(job.root.transaction_id,job.id);
		if (!committed) return false;
		if (committed.id != job.root.transaction_id || committed.request_id != job.id ||
			type(committed.version) != 'int' || committed.version < 1 || !root_proof_unchanged(s,job))
			die('ap_restore_unverified: Committed Root restoration no longer matches its frozen AP proof');
		all_disabled(s,false);
		job.root.status='committed'; finish(s,'complete'); return true;
	}
	function prepare(id) {
		pairing.root(); validate(id);
		let s = pairing.state();
		all_disabled(s);
		if (s.lifecycle?.id == id) return public_lifecycle(s.lifecycle);
		if (configuration_busy(s, io) || lifecycle_busy(s)) die('busy: A configuration operation is pending');
		if (history_used(s, 'lifecycle', id))
			die('request_reused: Mesh operation has already completed');
		let plan = io.local.mesh_preview(false);
		let job = { id, enabled: false, phase: 'preparing', boot: io.boot(), deadline: io.now() + 300,
			created: time(), root: { status: length(plan.errors) ? 'failed' : 'ready', plan }, nodes: {} };
		for (let member in values(s.members)) {
			if (!member.authorized) continue;
			job.nodes[member.id] = { status: 'disabled', plan: null };
		}
		s.lifecycle = job; save(s); tick();
		return public_lifecycle(pairing.state().lifecycle);
	}
	function node_prepare(node_id, enabled, id) {
		pairing.root(); validate(id);
		if (type(enabled) != 'bool') die('invalid_request: Invalid Mesh target state');
		let s = pairing.state(), m = s.members[node_id];
		if (!m?.authorized) die('not_authorized: Node is not authorized');
		if (s.lifecycle?.id == id) {
			if (s.lifecycle.node_id != node_id || s.lifecycle.enabled !== enabled) die('request_reused: Mesh target changed');
			return public_lifecycle(s.lifecycle);
		}
		if (configuration_busy(s, io) || lifecycle_busy(s)) die('busy: A configuration operation is pending');
		if (!s.intent || io.local.status().mesh_enabled !== true) die('mesh_disabled: Enable Root before changing AP Mesh');
		if (!fresh(node_id)) die('node_offline: Bring the AP online before changing Mesh');
		if (enabled && m.control_protocol !== 1)
			die('control_protocol_unsupported: Wait for AP capability reports or update Root and AP together');
		if (m.report?.configured !== true) die('invalid_state: Finish AP configuration before changing Mesh');
		if (history_used(s, 'lifecycle', id)) die('request_reused: Mesh operation has already completed');
		let job = { id, node_id, enabled, phase: 'preparing', boot: io.boot(), deadline: io.now() + 300,
			created: time(), root: { status: 'skipped' }, nodes: {} };
		let control = enabled ? adopt_leases(s)[node_id] : null;
		job.nodes[node_id] = { status: 'pending', plan: null, control };
		command(job, job.nodes[node_id], 'mesh_prepare'); s.lifecycle = job; save(s);
		return public_lifecycle(job);
	}
	function apply(id, approval, takeover) {
		pairing.root();
		let s = pairing.state(), job = s.lifecycle;
		if (!job || job.id != id) die('not_found: Mesh stop operation not found');
		if (takeover !== true) die('takeover_required: Explicit Mesh restore approval is required');
		if (index(['applying', 'root_applying', 'awaiting_confirm', 'complete'], job.phase) >= 0)
			return public_lifecycle(job);
		if (job.phase != 'ready' || job.boot != io.boot() || io.now() >= job.deadline)
			die('invalid_state: All AP restore previews must be ready');
		if (!equal(approval, public_lifecycle(job))) die('preview_changed: Review the updated restore previews');
		if (job.enabled && !equal(job.nodes[job.node_id]?.control, lease_for(s, job.node_id)))
			die('preview_changed: Controller control address lease changed');
		if (!job.node_id) all_disabled(s);
		if (length(filter(keys(job.nodes), (id) => !fresh(id))))
			die('node_offline: Every active AP must be online before restoring');
		job.phase = 'applying'; job.deadline = io.now() + 180 * (length(keys(job.nodes)) + 1);
		save(s); return public_lifecycle(job);
	}
	function cancel(id, phase, failure) {
		pairing.root();
		let s = pairing.state(), job = s.lifecycle;
		if (!job || job.id != id) die('not_found: Mesh stop operation not found');
		if (index(TERMINAL, job.phase) >= 0) return public_lifecycle(job);
		if (recover_root_commit(s,job)) return public_lifecycle(job);
		if (job.root.transaction_id && job.root.status != 'committed') {
			let local=io.local.status().active;
			if (local?.id != job.root.transaction_id || local.request_id != job.id || local.kind != 'release' ||
				local.mesh_enabled !== false || local.status == 'committed') {
				job.root.status='unverified';job.root.error='root_restore_unverified';
				finish(s,'partial','Root restoration journal changed; existing configuration is preserved');
				return public_lifecycle(job);
			}
			if (index(['rolled_back','rollback_conflict','expired'],local.status) < 0)
				io.local.rollback(job.root.transaction_id);
			else job.root.status=local.status;
		}
		for (let node in values(job.nodes)) {
			if (index(['applying', 'awaiting_confirm', 'confirming'], node.status) >= 0)
				command(job, node, 'mesh_rollback');
			else node.command = null;
		}
		finish(s, length(filter(values(job.nodes), (n) => n.changed)) ? 'partial' : phase || 'cancelled',
			failure || 'Unconfirmed changes are rolled back; APs already disabled remain disabled');
		return public_lifecycle(job);
	}
	function report(s, member, report) {
		let changed = false, ack = report.command, job = s.lifecycle, node = job?.nodes[member.id];
		if (report.mesh_enabled === true && member.mesh_restore_receipt != null) {
			delete member.mesh_restore_receipt; changed=true;
		}
		function restoration() {
			let receipt=record_restoration(s,pairing.root(),member,report);
			if (receipt && !equal(receipt,member.mesh_restore_receipt)) {
				member.mesh_restore_receipt=receipt; changed=true;
			}
			return changed;
		}
		if (type(report.mesh_enabled) == 'bool' && report.configured === true &&
			(!report.transaction || index(LOCAL_TERMINAL, report.transaction.status) >= 0)) {
			let paused = !report.mesh_enabled;
			if (member.mesh_paused !== paused) { member.mesh_paused = paused; changed = true; }
		}
		if (member.mesh_mode && ack?.mesh === true && ack.transaction == member.mesh_mode.id) {
			if (member.mesh_mode.status != ack.status) {
				member.mesh_mode.status = ack.status; member.mesh_mode.error = ack.error || null; changed = true;
			}
		}
		if (!node?.command || ack?.id != node.command.id || ack.mesh !== true || ack.transaction != job.id)
			return restoration();
		if (node.command.action == 'mesh_rollback' && index(LOCAL_TERMINAL, ack.status) >= 0) {
			node.command = null; node.status = ack.status; node.conflicts = ack.conflicts || [];
		} else if (ack.status == 'error' || index(['rolled_back', 'rollback_conflict', 'expired'], ack.status) >= 0) {
			if (node.command.action == 'mesh_prepare' && type(ack.plan) == 'object' &&
				type(ack.plan.ops) == 'array' && type(ack.plan.errors) == 'array') node.plan = clone(ack.plan);
			node.status = ack.status == 'error' ? 'failed' : ack.status;
			node.error = ack.error || 'local_recovery'; node.conflicts = ack.conflicts || []; node.command = null;
		} else if (node.command.action == 'mesh_prepare' && index(['ready', 'disabled', 'enabled'], ack.status) >= 0) {
			if (ack.status == 'ready' && (type(ack.plan) != 'object' || type(ack.plan.ops) != 'array' || length(ack.plan.errors || [])))
				die('protocol_error: Invalid AP restore preview');
			node.plan = ack.plan; node.status = ack.status; node.command = null;
		} else if (node.command.action == 'mesh_apply' && ack.status == 'awaiting_confirm' && report.health?.ok === true) {
			node.status = 'awaiting_confirm'; node.command = null;
		} else if ((node.command.action == 'mesh_confirm' || node.command.action == 'mesh_apply' && job.enabled === false) &&
			ack.status == 'committed' && ack.health_confirmed === true && report.mesh_enabled === (job.enabled === true)) {
			node.status = job.enabled ? 'enabled' : 'disabled'; node.command = null;
			node.changed = true; member.mesh_paused = !job.enabled;
		} else return changed;
		restoration(); return true;
	}
	function request(s, id, r) {
		let root = pairing.root(), m = s.members[id];
		if (!m?.authorized) die('not_authorized: Node is not authorized');
		if (r.action == 'mesh_abort') {
			if (m.mesh_mode?.id == r.request_id && m.mesh_mode.status == 'reserved') {
				m.mesh_mode.status = 'no_change'; save(s);
			}
			return {};
		}
		if (r.action == 'mesh_check') {
			if (m.mesh_mode?.id != r.request_id || m.mesh_mode.version != r.version || s.version != r.version ||
				m.mesh_mode.boot != io.boot() || io.now() >= m.mesh_mode.deadline ||
				index(LOCAL_TERMINAL, m.mesh_mode.status) >= 0 || lifecycle_busy({ ...s, members: {} }))
				die('configuration_conflict: Mesh reservation changed');
			if (m.mesh_mode.enabled && !equal(m.mesh_mode.control, lease_for(s, id)))
				die('configuration_conflict: Controller control address lease changed');
			return { version: s.version };
		}
		if (configuration_busy(s, io) || lifecycle_busy(s) && m.mesh_mode?.id != r.request_id)
			die('busy: A configuration operation is pending');
		if (!s.intent || io.local.repair_status?.()?.paused === true)
			die('mesh_disabled: Controller Mesh is disabled');
		let control = r.enabled === true ? lease_for(s, id) : null;
		if (r.action == 'mesh_reserve') {
			validate(r.request_id);
			if (r.version != s.version) die('preview_changed: Root intent version changed');
			if (m.mesh_mode?.id != r.request_id) {
				if (r.enabled === true) adopt_leases(s);
				m.mesh_mode = { id: r.request_id, version: s.version, enabled: r.enabled === true,
					control, status: 'reserved', boot: io.boot(), deadline: io.now() + 420 };
				save(s);
			} else if (m.mesh_mode.enabled !== (r.enabled === true) || !equal(m.mesh_mode.control, control))
				die('request_reused: Mesh target changed');
		}
		return { intent: clone(s.intent), version: s.version, root_mac: mesh_mac(root.id), control,
			bootstrap:io.bootstrap_wifi?.() || [] };
	}
	function confirm(id) {
		pairing.root();
		let s = pairing.state(), job = s.lifecycle;
		if (!job || job.root.transaction_id != id || index(['root_applying', 'awaiting_confirm'], job.phase) < 0)
			die('invalid_state: Root shutdown is not awaiting confirmation');
		if (length(filter(values(job.nodes), (n) => n.status != 'disabled')))
			die('invalid_state: All APs must be restored before disabling Root');
		if (recover_root_commit(s,job)) return {id,status:'committed',kind:'release',mesh_enabled:false};
		if (job.boot != io.boot() || io.now() >= job.deadline || !root_proof_unchanged(s,job))
			die('preview_changed: AP restoration proof changed after Root restoration began');
		all_disabled(s,false);
		let result = io.local.confirm(id); job.root.status = result.status;
		finish(s, 'complete'); return result;
	}
	tick = function() {
		let s = pairing.state(), job = s.lifecycle, changed = false;
		for (let m in values(s.members)) {
			if (m.mesh_mode && index(LOCAL_TERMINAL, m.mesh_mode.status) < 0 &&
				(m.mesh_mode.boot != io.boot() || io.now() >= m.mesh_mode.deadline)) {
				m.mesh_mode.status = 'expired'; changed = true;
			}
		}
		if (changed) save(s);
		if (!job || index(TERMINAL, job.phase) >= 0) return;
		try { if (recover_root_commit(s,job)) return; }
		catch(e) {
			if (index(e.message || '', 'storage_error:') == 0 || index(e.message || '', 'busy:') == 0) die(e.message);
			job.root.status='unverified';job.root.error='root_restore_unverified';
			finish(s,'partial','Committed Root restoration cannot be verified; external values are preserved');return;
		}
		if (job.boot != io.boot() || io.now() >= job.deadline) {
			cancel(job.id, 'expired', 'Mesh shutdown expired or Root restarted; unconfirmed changes recover independently'); return;
		}
		if (job.root.status == 'failed' || length(filter(values(job.nodes), (n) =>
			index(['failed', 'rolled_back', 'rollback_conflict', 'expired'], n.status) >= 0))) {
			cancel(job.id, 'failed', 'AP Mesh operation failed; Root remains enabled'); return;
		}
		let target = job.enabled ? 'enabled' : 'disabled';
		if (job.phase == 'preparing' && !length(filter(values(job.nodes), (n) => index(['ready', target], n.status) < 0))) {
			if (job.node_id && job.nodes[job.node_id].status == target) { finish(s, 'complete'); return; }
			job.phase = 'ready'; save(s); return;
		}
		if (job.phase == 'applying') {
			let id = filter(keys(job.nodes), (id) => job.nodes[id].status != target)[0];
			if (id) {
				let n = job.nodes[id];
				if (n.status == 'ready') { n.status = 'applying'; command(job, n, 'mesh_apply'); save(s); }
				else if (n.status == 'awaiting_confirm') { n.status = 'confirming'; command(job, n, 'mesh_confirm'); save(s); }
				return;
			}
			if (job.node_id) { finish(s, 'complete'); return; }
			try {
				all_disabled(s);
				let staged = io.local.mesh_stage(false, null, job.id, true, job.root.plan);
				job.root.transaction_id = staged.id; job.root.status = staged.status;
				all_disabled(s);
				job.phase = 'root_applying'; job.shutdown_guard=shutdown_guard(s,pairing.root(),job);
				save(s); io.local.apply(staged.id);
			} catch (e) {
				if (match(e.message || '', /^busy:/)) return;
				if (job.root.transaction_id) try { io.local.rollback(job.root.transaction_id); } catch(ignored) {}
				finish(s, 'failed', 'Root restore preview changed; Root remains enabled');
			}
			return;
		}
		if (index(['root_applying', 'awaiting_confirm'], job.phase) >= 0) {
			let local = io.local.status();
			if (local.active?.id != job.root.transaction_id) { finish(s, 'partial', 'Root transaction changed'); return; }
			if (index(['rolled_back', 'rollback_conflict', 'expired'], local.active.status) >= 0) {
				job.root.status = local.active.status; finish(s, 'partial', 'Root independently recovered'); return;
			}
			if (local.active.status == 'awaiting_confirm' && job.phase != 'awaiting_confirm') {
				job.root.status = 'awaiting_confirm'; job.phase = 'awaiting_confirm'; save(s);
			}
		}
	};
	return { prepare, node_prepare, apply, cancel, report, request, tick, confirm };
}
