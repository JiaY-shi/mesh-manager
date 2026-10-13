// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { history_used } from './history_retention.uc';
import { effective_settings } from './local_settings.uc';
import * as crypto from 'mesh_crypto';
import { clone, equal } from './model.uc';
import { mesh_mac, local_intent } from './extended.uc';
import { lifecycle_busy } from './lifecycle.uc';
import { adopt_leases, lease_for } from './control_lease.uc';

const TERMINAL = ['committed', 'failed', 'rolled_back', 'rollback_conflict', 'expired'];
export function controller_repair_busy(io) {
	let active = io.local.repair_status?.();
	return active && (active.kind == 'repair' || active.kind == 'overrides' || active.kind == 'release' || active.mesh_enabled != null) &&
		index(TERMINAL, active.status) < 0;
}
export function repair_pending(s) {
	return length(filter(values(s.members), (m) => m.authorized && m.repair &&
		index(TERMINAL, m.repair.status) < 0)) > 0;
}
export function cluster_busy(s) {
	return lifecycle_busy(s) || s.active && (index(['complete', 'partial', 'failed', 'rolled_back', 'expired'],
		s.active.phase) < 0 || length(filter(values(s.active.nodes),
		(n) => index(['apply', 'confirm', 'rollback'], n.command?.action) >= 0)) > 0);
}
export function public_repair(job) {
	if (!job) return null;
	return { id: job.id, source: job.source, purpose: job.purpose || 'repair', status: job.status, version: job.version,
		created: job.created, plan: job.plan || null, error: job.error || null,
		conflicts: job.conflicts || [] };
}
function report_busy(report) {
	return report?.transaction && index(['committed', 'rolled_back', 'rollback_conflict', 'expired'],
		report.transaction.status) < 0;
}
export function repair_service(io, pairing) {
	function save(s) { io.save('cluster.json', s); }
	function validate(id) {
		if (!match(id || '', /^[a-zA-Z0-9_-]{16,64}$/))
			die('invalid_request: Invalid repair request ID');
	}
	function member(s, id) {
		let m = s.members[id];
		if (!m?.authorized) die('not_authorized: Node identity is not authorized');
		if (m.mesh_paused === true) die('mesh_disabled: Enable the AP before repairing its Mesh settings');
		return m;
	}
	function controller_target() {
		let root = pairing.root(), s = pairing.state();
		if (cluster_busy(s) || repair_pending(s)) die('busy: A cluster operation is pending');
		if (!s.intent) die('not_managed: Controller has no confirmed network intent');
		if (io.local.repair_status?.()?.paused === true) die('mesh_disabled: Controller Mesh is disabled');
		return { intent: local_intent(s.intent, effective_settings(root, io.load('state.json')), true, root.gateway, root.id), version: s.version };
	}
	function local_preview() {
		let target = controller_target();
		return { ...io.local.repair_preview(target.intent), root_version: target.version };
	}
	function local_stage(id, approval, takeover) {
		validate(id);
		if (takeover !== true) die('takeover_required: Explicit repair approval is required');
		let target = controller_target(), plan = clone(approval);
		if (plan?.root_version != target.version) die('preview_changed: Controller intent version changed');
		delete plan.root_version;
		return io.local.repair_stage(target.intent, crypto.sha256('root-repair:' + id), true, plan);
	}
	function local_confirm(id) {
		pairing.root();
		let active = io.local.repair_status?.();
		if (active?.kind != 'repair' || active.id != id)
			die('invalid_state: Repair confirmation does not match the controller transaction');
		return io.local.confirm(id);
	}
	function finish(s, m, status, error) {
		let job = m.repair;
		job.status = status;
		job.error = error || job.error || null;
		job.command = null;
		delete job.intent;
		delete job.control;
		delete job.plan;
		s.repair_history ||= [];
		push(s.repair_history, { node_id: m.id, ...public_repair(job), timestamp: time() });
		if (length(s.repair_history) > 32) shift(s.repair_history);
	}
	function command(job, action) {
		job.command = { id: job.id + '-' + action, transaction: job.id, action,
			version: job.version,
			intent: index(['repair_prepare', 'repair_apply'], action) >= 0 ? job.intent : null,
			approval: action == 'repair_apply' ? job.plan : null,
			control: job.control,
			root_mac: mesh_mac(pairing.root().id) };
	}
	function enqueue(node_id, id) {
		pairing.root(); validate(id);
		let s = pairing.state(), m = member(s, node_id);
		if (!s.intent) die('not_managed: Controller has no confirmed network intent');
		if (m.repair?.id == id) {
			if (m.repair.source != 'root') die('request_reused: Repair request belongs to another operation');
			return public_repair(m.repair);
		}
		if (m.repair && index(TERMINAL, m.repair.status) < 0)
			die('busy: A repair request is already pending for this node');
		if (history_used(s, 'repair', id))
			die('request_reused: Repair request already completed');
		if (m.control_protocol !== 1)
			die('control_protocol_unsupported: Wait for AP capability reports or update Root and AP together');
		adopt_leases(s);
		m.repair = { id, source: 'root', status: 'queued', created: time(), version: null };
		save(s);
		return public_repair(m.repair);
	}
	function desired(s, id) {
		member(s, id);
		if (cluster_busy(s) || controller_repair_busy(io)) die('busy: A cluster transaction is active');
		if (!s.intent) die('not_managed: Controller has no confirmed network intent');
		return { intent: clone(s.intent), version: s.version, root_mac: mesh_mac(pairing.root().id), control: lease_for(s, id) };
	}
	function reserve(s, node_id, id, version, purpose) {
		purpose ||= 'repair';
		if (index(['repair', 'overrides'], purpose) < 0) die('invalid_request: Invalid reservation purpose');
		validate(id);
		let target = desired(s, node_id), m = member(s, node_id), job = m.repair;
		if (job?.id == id) {
			if (job.source != 'ap' || (job.purpose || 'repair') != purpose ||
				index(['reserved', 'applying', 'awaiting_confirm'], job.status) < 0)
				die('request_reused: Repair request already used');
			if (job.boot != io.boot() || io.now() >= job.deadline)
				die('preview_changed: Controller repair reservation expired');
			if (!equal(job.control, target.control)) die('preview_changed: Controller control address lease changed');
			return { intent: clone(job.intent), version: job.version, root_mac: target.root_mac, control: clone(job.control) };
		}
		if (job && index(TERMINAL, job.status) < 0)
			die('busy: A repair request is already pending for this node');
		if (version != s.version) die('preview_changed: Controller intent version changed');
		if (history_used(s, 'repair', id))
			die('request_reused: Repair request already completed');
		adopt_leases(s);
		m.repair = { id, source: 'ap', purpose, status: 'reserved', intent: clone(target.intent), control: clone(target.control),
			version: s.version, boot: io.boot(), deadline: io.now() + 420, created: time() };
		save(s);
		return target;
	}
	function apply(node_id, id, approval, takeover) {
		pairing.root();
		let s = pairing.state(), m = member(s, node_id), job = m.repair;
		if (!job || job.id != id || job.source != 'root') die('not_found: Repair request not found');
		if (takeover !== true) die('takeover_required: Explicit repair approval is required');
		if (index(['applying', 'awaiting_confirm', 'confirming', 'committed'], job.status) >= 0)
			return public_repair(job);
		if (cluster_busy(s) || controller_repair_busy(io)) die('busy: A cluster transaction is active');
		if (job.status != 'ready' || job.boot != io.boot() || io.now() >= job.deadline ||
			job.version != s.version || !equal(approval, job.plan) || !equal(job.control, lease_for(s, node_id)))
			die('preview_changed: Repair preview changed or expired');
		job.status = 'applying'; job.deadline = io.now() + 150;
		command(job, 'repair_apply'); save(s);
		return public_repair(job);
	}
	function cancel(s, m) {
		let job = m.repair;
		if (index(TERMINAL, job.status) >= 0) return;
		if (index(['queued', 'preparing', 'ready'], job.status) >= 0) finish(s, m, 'rolled_back');
		else { job.status = 'rolling_back'; command(job, 'repair_rollback'); }
	}
	function rollback(node_id, id) {
		pairing.root();
		let s = pairing.state(), m = member(s, node_id);
		if (m.repair?.id != id) die('not_found: Repair request not found');
		if (m.repair.status == 'committed') die('invalid_state: Confirmed repair cannot be rolled back');
		cancel(s, m); save(s);
		return public_repair(m.repair);
	}
	function request(s, id, r) {
		if (r.action == 'repair_intent') return desired(s, id);
		if (r.action == 'repair_reserve') return reserve(s, id, r.request_id, r.version, r.purpose);
		if (r.action == 'repair_check') {
			let job = member(s, id).repair;
			if (job?.id != r.request_id || job.version != r.version || job.boot != io.boot() ||
				io.now() >= job.deadline || index(['reserved', 'applying', 'awaiting_confirm'], job.status) < 0 ||
				!equal(job.control, lease_for(s, id)))
				die('invalid_state: Controller repair reservation is no longer active');
			return { status: job.status };
		}
		if (r.action == 'repair_abort') {
			let m = member(s, id);
			if (m.repair?.id != r.request_id || m.repair.source != 'ap')
				die('not_found: Repair reservation not found');
			cancel(s, m); save(s);
			return public_repair(m.repair);
		}
		die('invalid_method: Invalid repair request');
	}
	function report(s, m, report) {
		let job = m.repair, ack = report.command;
		if (!job || index(TERMINAL, job.status) >= 0 || !ack?.repair ||
			ack.transaction != job.id || ack.version != job.version) return false;
		if (job.source == 'root' && (!job.command || ack.id != job.command.id)) return false;
		if (index(['rolled_back', 'rollback_conflict', 'expired', 'no_change'], ack.status) >= 0) {
			job.conflicts = ack.conflicts || [];
			finish(s, m, ack.status == 'no_change' ? 'rolled_back' : ack.status, ack.error);
			return true;
		}
		if (ack.status == 'error') {
			job.error = ack.error || 'node_error';
			if (index(['queued', 'preparing', 'ready'], job.status) >= 0) finish(s, m, 'failed');
			else if (job.status != 'rolling_back') {
				job.status = 'rolling_back'; command(job, 'repair_rollback');
			} else return false;
			return true;
		}
		if (job.command?.action == 'repair_prepare' && ack.status == 'ready') {
			if (type(ack.plan) != 'object' || type(ack.plan.ops) != 'array' ||
				length(ack.plan.errors || []) || type(ack.plan.binding?.token) != 'string')
				die('protocol_error: Invalid repair preview');
			job.plan = clone(ack.plan); job.status = 'ready'; job.command = null;
			return true;
		}
		if (ack.status == 'awaiting_confirm' && report.health?.ok === true &&
			index(['reserved', 'applying'], job.status) >= 0) {
			job.status = 'awaiting_confirm'; job.command = null;
			return true;
		}
		if (ack.status == 'committed' && (job.source == 'ap' || job.command?.action == 'repair_confirm')) {
			finish(s, m, 'committed'); return true;
		}
		return false;
	}
	function tick() {
		let s = pairing.state(), changed = false;
		for (let id in keys(s.members)) {
			let m = s.members[id], job = m.repair;
			if (!job || index(TERMINAL, job.status) >= 0) continue;
			if (!m.authorized) { finish(s, m, 'failed', 'not_authorized'); changed = true; continue; }
			if (job.status == 'queued') {
				let seen = io.presence?.(id);
				if (cluster_busy(s) || controller_repair_busy(io) || seen?.boot != io.boot() || io.now() - seen.seen >= 15 ||
					(report_busy(m.report))) continue;
				job.intent = clone(s.intent); job.version = s.version; job.boot = io.boot();
				job.control = lease_for(s, id);
				job.deadline = io.now() + 300; job.status = 'preparing';
				command(job, 'repair_prepare'); changed = true;
			} else if (job.status != 'rolling_back' &&
				(job.boot != io.boot() || io.now() >= job.deadline)) {
				job.error = 'repair_timeout';
				if (index(['preparing', 'ready'], job.status) >= 0) finish(s, m, 'expired');
				else { job.status = 'rolling_back'; command(job, 'repair_rollback'); }
				changed = true;
			} else if (job.status == 'awaiting_confirm' && job.source == 'root') {
				job.status = 'confirming'; command(job, 'repair_confirm'); changed = true;
			}
		}
		if (changed) save(s);
	}
	return { enqueue, apply, rollback, request, report, tick, local_preview, local_stage, local_confirm };
}
