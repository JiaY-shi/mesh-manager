// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { history_used, history_version } from './history_retention.uc';
import { settings_identity } from './local_settings.uc';
import * as crypto from 'mesh_crypto';
import { clone, equal } from './model.uc';
import { local_intent, mesh_mac, validate_controller_management } from './extended.uc';
import { adopt_leases, lease_for } from './control_lease.uc';
import { repair_service, repair_pending, cluster_busy, controller_repair_busy } from './repair.uc';
import { lifecycle_service, lifecycle_busy } from './lifecycle.uc';
import { handoff_receipt } from './handoff_controller.uc';
import { restored_member } from './restoration.uc';

export function public_active(a, plans) {
	if (!a) return null;
	let result = {
		id: a.id,
		phase: a.phase,
		version: a.version,
		failure: a.failure || null,
		created: a.created,
			nodes: map(keys(a.nodes), (id) => ({ id, ...a.nodes[id], command: null, intent: null, control: null })),
		root: { status: a.root.status, plan: a.root.plan, error: a.root.error || null },
		maintenance: a.maintenance
	};
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
export function cluster_service(io, pairing) {
	let repair = repair_service(io, pairing);
	let lifecycle = lifecycle_service(io, pairing);
	function load() {
		return pairing.state();
	}
	function save(s) {
		io.save('cluster.json', s);
	}
	function finish(s, phase, reason) {
		s.active.phase = phase;
		s.active.failure = reason || null;
		push(s.history, {
			id: s.active.id,
			version: s.active.version,
			phase,
			failure: reason || null,
			nodes: map(keys(s.active.nodes), (id) => ({ id, status: s.active.nodes[id].status })),
			timestamp: time()
		});
		if (length(s.history) > 32) shift(s.history);
		save(s);
	}
	function command(a, id, action) {
		let node = a.nodes[id];
		node.command = {
			id: a.id + '-' + action,
			action,
			transaction: a.id,
			version: a.version,
			intent: action == 'prepare' || action == 'apply' ? a.intent : null,
			approval: action == 'apply' ? node.plan : null,
			control: node.control,
			peers: map(
				filter(keys(a.nodes), (n) => n != id),
				(n) => mesh_mac(n)
			),
			root_mac: mesh_mac(pairing.root().id), bootstrap:io.bootstrap_wifi?.() || []
		};
	}
	function preflight(intent, request_id, maintenance) {
		let root = pairing.root(),
			s = load();
		root = settings_identity(root, io.load('state.json'));
		validate_controller_management(root.overrides, root.address);
		if (controller_repair_busy(io)) die('busy: Controller configuration repair is pending');
		if (io.local.repair_status?.()?.paused === true) die('mesh_disabled: Enable controller Mesh first');
		intent = clone(intent);
		if (intent?.wifi && intent.wifi.key == null && s.intent?.wifi?.key)
			intent.wifi.key = s.intent.wifi.key;
		if (
			intent?.backhaul &&
			intent.backhaul.key == null &&
			intent.backhaul.mode == s.intent?.backhaul?.mode &&
			s.intent.backhaul.key
		)
			intent.backhaul.key = s.intent.backhaul.key;
		if (!match(request_id || '', /^[a-zA-Z0-9_-]{16,64}$/))
			die('invalid_request: Invalid cluster request ID');
		if (
			type(intent) != 'object' ||
			intent.schema != 2 ||
			length(
				filter(
					keys(intent),
					(k) => index(['schema', 'name', 'wifi', 'backhaul', 'networks'], k) < 0
				)
			)
		)
			die('invalid_intent: Expected unified schema 2 intent');
		if (s.active?.id == request_id) {
			if (!equal(s.active.intent, intent)) die('request_reused: Request belongs to another intent');
			return public_active(s.active);
		}
		if (
			s.active &&
			index(['complete', 'partial', 'failed', 'rolled_back', 'expired'], s.active.phase) < 0
		)
			die('busy: A cluster transaction is active');
		if (history_used(s, 'cluster', request_id))
			die('request_reused: Cluster request already completed');
		if (repair_pending(s)) die('busy: Node configuration repair is pending');
		if (cluster_busy(s)) die('busy: Node recovery commands are pending');
		if (s.intent && !equal(s.intent.backhaul, intent.backhaul) && maintenance !== true)
			die(
				'maintenance_required: Backhaul channel or credentials require coordinated wired maintenance'
			);
		let local = local_intent(intent, root.overrides, true, root.gateway, root.id),
			plan = io.local.preview(local);
		if (length(plan.errors)) die('preflight_failed: Controller candidate failed preflight');
		let leases = adopt_leases(s);
		for (let m in values(s.members))
			if (m.authorized && m.mesh_paused !== true && m.control_protocol !== 1)
				die('control_protocol_unsupported: Wait for AP capability reports or update Root and AP together');
		// A partially committed batch consumes its version even if the Root rolled
		// back. A compensating intent must never reuse that version on an AP.
		let previous_version = max(s.version, s.active?.version || 0, history_version(s));
		for (let entry in [...values(s.members), ...(s.history || [])])
			previous_version = max(previous_version, entry.version || 0);
		let a = {
			id: request_id,
			version: previous_version + 1,
			phase: 'preflight',
			intent: clone(intent),
			boot: io.boot(),
			deadline: io.now() + 300,
			created: time(),
			maintenance: maintenance === true,
			root: { status: 'ready', plan, intent: local },
			nodes: {}
		};
		for (let id in keys(s.members))
			if (s.members[id].authorized && s.members[id].mesh_paused !== true) {
				a.nodes[id] = { status: 'pending', plan: null, error: null, command: null, control: leases[id] };
				command(a, id, 'prepare');
			}
		s.active = a;
		save(s);
		if (!length(keys(a.nodes))) {
			a.phase = 'ready';
			save(s);
		}
		return public_active(a);
	}
	function apply(id, approval, takeover) {
		pairing.root();
		let s = load(),
			a = s.active;
		if (!a || a.id != id) die('not_found: Cluster transaction not found');
		if (takeover !== true) die('takeover_required: Explicit cluster takeover approval required');
		if (a.phase == 'applying' || a.phase == 'confirming' || a.phase == 'complete')
			return public_active(a);
		if (a.phase != 'ready' || a.boot != io.boot() || io.now() >= a.deadline)
			die('invalid_state: All-node preflight is not ready');
		if (!equal(approval, public_active(a))) die('preview_changed: Review updated all-node preview');
		for (let node_id in keys(a.nodes))
			if (!equal(a.nodes[node_id].control, lease_for(s, node_id)))
				die('preview_changed: Controller control address lease changed');
		if (
			a.maintenance &&
			length(filter(keys(a.nodes), (id) => {
				let seen = io.presence?.(id), path = s.members[id]?.report?.backhaul;
				return seen?.boot != io.boot() || io.now() - (seen?.seen || 0) >= 15 ||
					path?.active != 'wired' || path?.wired !== true;
			}))
		)
			die('maintenance_required: All APs must report an authenticated wired path');
		// Stage the controller only when its batch is ready; a staged local candidate
		// must not expire while earlier AP batches are still converging.
		a.root_first = a.intent.backhaul.mode != 'wired';
		a.phase = 'applying';
		a.deadline = io.now() + 240 + int((length(keys(a.nodes)) + 1) / 2) * 120;
		save(s);
		return public_active(a);
	}
	function rollback(id) {
		pairing.root();
		let s = load(),
			a = s.active;
		if (!a || a.id != id) die('not_found: Cluster transaction not found');
		if (index(['complete', 'partial', 'failed', 'rolled_back', 'expired'], a.phase) >= 0)
			die('invalid_state: Completed transaction requires a new compensating change');
		a.phase = 'rolling_back';
		for (let id in keys(a.nodes))
			if (a.nodes[id].status != 'committed') command(a, id, 'rollback');
		// Persist cancellation before asking the independent local recovery worker.
		// A busy local lock must not discard the user's cancellation request.
		save(s);
		return public_active(a);
	}
	function advance_rollback(s) {
		let a = s.active, root = a.root, changed = false;
		if (root.status != 'committed') {
			let status = 'no_change';
			if (root.transaction_id) {
				let local;
				try { local = io.local.status(); }
				catch (e) { if (match(e.message || '', /^busy: /)) return; die(e.message); }
				if (local.active?.id != root.transaction_id) {
					status = 'failed'; root.error = 'root_state_error: Controller local transaction changed';
				} else if (index(['committed', 'rolled_back', 'rollback_conflict', 'expired'], local.active.status) >= 0) {
					status = local.active.status;
					if (status == 'committed') { s.version = a.version; s.intent = clone(a.intent); }
				} else {
					try { io.local.rollback(root.transaction_id); }
					catch (e) { if (match(e.message || '', /^busy: /)) return; die(e.message); }
					return;
				}
			}
			if (root.status != status) { root.status = status; changed = true; }
		}
		let statuses = [root.status, ...map(values(a.nodes), node => node.status)];
		if (length(filter(values(a.nodes), node => node.command != null)) ||
			length(filter(statuses, status => index(['committed', 'rolled_back', 'rollback_conflict',
			'no_change', 'failed', 'expired'], status) < 0))) {
			if (changed) save(s);
			return;
		}
		if (index(statuses, 'committed') >= 0)
			finish(s, 'partial', 'Cancellation preserved committed batches; apply a new compensating change');
		else if (length(filter(statuses, status => index(['rollback_conflict', 'failed', 'expired'], status) >= 0)))
			finish(s, 'partial', 'Rollback requires review; inspect each node recovery result');
		else finish(s, 'rolled_back', a.failure);
	}
	function peer(id, r) {
		let root = pairing.root(),
			s = load(),
			m = s.members[id];
		if (!m?.authorized) {
			if (m?.authorized===false && type(m.removed)=='int' && r?.protocol===1 &&
				r.network_id==root.network_id && r.action=='poll' && restored_member(s,root,m))
				return {controller_id:root.id,network_id:root.network_id,
					authorization:{status:'revoked',node_id:id,certificate:m.certificate,removed:m.removed,
						restoration:{request_id:m.mesh_restore_receipt.request_id,
							transaction_id:m.mesh_restore_receipt.transaction_id,
							version:m.mesh_restore_receipt.version,local_version:m.mesh_restore_receipt.local_version}}};
			die('not_authorized: Node identity is not authorized');
		}
		if (
			type(r) != 'object' ||
			r.protocol != 1 ||
			r.network_id != root.network_id ||
			index(['poll', 'probe', 'repair_intent', 'repair_reserve', 'repair_abort', 'repair_check',
				'mesh_intent', 'mesh_reserve', 'mesh_abort', 'mesh_check', 'handoff_check', 'standby_hint'], r.action) < 0
		)
			die('invalid_request: Invalid node protocol');
		if (r.action == 'probe')
			return { controller_id: root.id, network_id: root.network_id, nonce: r.nonce };
		if (r.action == 'handoff_check') return handoff_receipt(root, s, id, r, io);
		if ((index(['repair_intent', 'repair_reserve'], r.action) >= 0 ||
			index(['mesh_intent', 'mesh_reserve'], r.action) >= 0 && r.enabled === true) && r.control_schema !== 1)
			die('control_protocol_unsupported: Update Root and AP together before changing configuration');
		if(r.action=='standby_hint')return {controller_id:root.id,network_id:root.network_id,
			bootstrap:io.bootstrap_wifi?.() || []};
		if (match(r.action, /^mesh_/)) return { controller_id: root.id, network_id: root.network_id,
			...lifecycle.request(s, id, r) };
		if (r.action != 'poll') return { controller_id: root.id, network_id: root.network_id,
			...repair.request(s, id, r) };
		// Path probes may continue while the configuration agent is unavailable.
		io.seen?.(id);
		let changed = false;
		let control_protocol = r.control_schema === 1 ? 1 : 0;
		if (m.control_protocol !== control_protocol) { m.control_protocol = control_protocol; changed = true; }
		if (r.report && type(r.report) == 'object' && length(sprintf('%J', r.report)) < 40000) {
			let report = io.sanitize_report(r.report);
			// Once observed, a committed configuration cannot be downgraded into
			// first-join bootstrap by a later zero-version report.
			if (m.control_configured!==true && (m.version>0 || m.report?.local_version>0 ||
				m.report?.configured===true || report.version>0 || report.local_version>0 || report.configured===true)) {
				m.control_configured=true; delete m.first_configuration; changed=true;
			}
			// Client observations are short-lived and never enter the flash journal.
			try { if (report.mesh_enabled === true && report.clients_complete === true) io.observe_clients?.(id, report.clients); }
			catch (e) {}
			delete report.clients;
			try { io.observe_report?.(id, report, { controller_id: root.id,
				network_id: root.network_id, certificate: m.certificate || null }); }
			catch (e) {}
			if (repair.report(s, m, report)) changed = true;
			if (lifecycle.report(s, m, report)) changed = true;
			// Wireless quality and sampled health belong to tmpfs, not the flash journal.
			let persisted = { ...report };
			delete persisted.health;
			if (type(persisted.backhaul)=='object') {
				persisted.backhaul = { ...persisted.backhaul };
				delete persisted.backhaul.quality;
			}
			if (!equal(m.report, persisted)) {
				m.report = persisted;
				m.version = report.version || 0;
				changed = true;
			}
			let a = s.active,
				node = a?.nodes[id],
				ack = report.command;
			if (node?.command && ack?.id == node.command.id) {
				if (ack.status == 'error' || (node.command.action != 'rollback' &&
					index(['rolled_back', 'rollback_conflict', 'expired'], ack.status) >= 0)) {
					node.status = 'failed';
					node.error = ack.error || (ack.status == 'error' ? 'Node command failed' :
						'Node independently rolled back its candidate');
					node.command = null;
					changed = true;
				} else if (node.command.action == 'prepare' && ack.status == 'ready') {
					if (
						type(ack.plan) != 'object' ||
						type(ack.plan.ops) != 'array' ||
						length(ack.plan.errors || [])
					)
						die('protocol_error: Invalid node preflight result');
					node.plan = ack.plan;
					node.status = 'ready';
					node.command = null;
					changed = true;
				} else if (
					node.command.action == 'apply' &&
					ack.status == 'awaiting_confirm' &&
					report.health?.ok === true &&
					(node.command.intent?.backhaul?.mode == 'wired' ||
						report.backhaul?.wireless_verified === true)
				) {
					node.status = 'awaiting_confirm';
					node.command = null;
					changed = true;
				} else if (node.command.action == 'confirm' && ack.status == 'committed') {
					node.status = 'committed';
					node.command = null;
					changed = true;
				} else if (
					node.command.action == 'rollback' &&
					index(['rolled_back', 'rollback_conflict', 'no_change'], ack.status) >= 0
				) {
					node.status = ack.status;
					node.command = null;
					changed = true;
				}
			}
		}
		if (changed) save(s);
		let a = s.active,
			node = a?.nodes[id];
		let next = s.lifecycle?.nodes[id]?.command || node?.command || m.repair?.command || null;
		if (
			!next &&
			m.mesh_paused !== true &&
			s.intent &&
			m.version < s.version &&
			(!a || index(['complete', 'failed', 'rolled_back', 'expired'], a.phase) >= 0) &&
			// Read controller-local gates only when this poll could deliver catchup.
			!lifecycle_busy(s) &&
			io.local.repair_status?.()?.paused !== true &&
			!repair_pending(s) &&
			!controller_repair_busy(io)
		) {
				next = {
				id: 'catchup-' + sprintf('%016d', s.version),
				action: 'catchup',
				version: s.version,
				intent: s.intent,
				control: lease_for(s, id),
					root_mac: mesh_mac(root.id), bootstrap:io.bootstrap_wifi?.() || []
				};
				if (m.control_configured!==true && m.version===0) {
					let tx=m.report?.transaction, ack=m.report?.command,
						request_id='mesh-'+next.id;
					if (tx?.kind=='configure' && tx.mesh_enabled==null && ack?.id==next.id &&
						ack.transaction_id==tx.id && index(['rolled_back','expired'],tx.status)>=0)
						request_id+='-'+substr(crypto.sha256(tx.id),0,16);
					let issued={id:next.id,version:next.version,request_id};
					if (!equal(m.first_configuration,issued)) { m.first_configuration=issued; save(s); }
				}
		}
		if (next?.intent != null && r.control_schema !== 1)
			die('control_protocol_unsupported: Update Root and AP together before accepting configuration');
		return {
			controller_id: root.id,
			network_id: root.network_id,
			version: s.version,
			command: next,
			peers: [mesh_mac(root.id)],
			name: m.name
		};
	}
	function advance_root(s) {
		let a = s.active;
		try {
			if (a.root.status == 'ready') {
				let staged = io.local.stage(a.root.intent, 'mesh-' + a.id, true, a.root.plan);
				a.root.transaction_id = staged.id;
				io.local.apply(staged.id);
				a.root.status = 'applying';
				save(s);
				return;
			}
			let local = io.local.status();
			if (local.active?.id != a.root.transaction_id)
				die('root_state_error: Controller local transaction changed');
			if (local.active.status == 'awaiting_confirm' && local.health?.ok) {
				io.local.confirm(a.root.transaction_id);
				a.root.status = 'committed';
				s.version = a.version;
				s.intent = clone(a.intent);
				save(s);
			} else if (index(['rolled_back', 'rollback_conflict', 'expired'], local.active.status) >= 0) {
				die('root_state_error: Controller local candidate was rolled back');
			}
		} catch (e) {
			// The local recovery daemon owns its own lock. A concurrent tick is
			// transient and must not abort a healthy cluster transaction.
			if (match(e.message || '', /^busy: /)) return;
			let reason = match(e.message || '', /^([a-z_]+): ([a-zA-Z0-9_.@ -]+)$/);
			a.root.error = reason
				? reason[1] + ': ' + reason[2]
				: 'controller_error: Controller candidate could not be applied or confirmed';
			if (a.root.transaction_id && a.root.status != 'committed') {
				try {
					io.local.rollback(a.root.transaction_id);
					a.root.status = 'rolling_back';
				} catch (rollback_error) {}
			}
			for (let id in keys(a.nodes))
				if (a.nodes[id].status != 'committed') {
					if (a.nodes[id].status == 'ready') a.nodes[id].status = 'no_change';
					else command(a, id, 'rollback');
				}
			finish(s, length(filter(values(a.nodes), (n) => n.status == 'committed'))
				? 'partial' : 'failed', a.root.error);
		}
	}
	function tick() {
		lifecycle.tick();
		if (lifecycle_busy(load())) return;
		repair.tick();
		let s = load(),
			a = s.active;
		if (!a || index(['complete', 'partial', 'failed', 'rolled_back', 'expired'], a.phase) >= 0)
			return;
		let statuses = map(values(a.nodes), (n) => n.status);
		if (a.boot != io.boot() || io.now() >= a.deadline) {
			if (index(['preflight', 'ready'], a.phase) >= 0) {
				for (let id in keys(a.nodes)) {
					a.nodes[id].command = null;
					a.nodes[id].status = 'no_change';
				}
				finish(s, 'expired', 'All-node preflight expired before any configuration was applied');
				return;
			}
			if (a.root.transaction_id && a.root.status != 'committed') {
				try {
					io.local.rollback(a.root.transaction_id);
				} catch (e) {}
			}
			for (let id in keys(a.nodes))
				if (a.nodes[id].status != 'committed') command(a, id, 'rollback');
			let committed = a.root.status == 'committed' || index(statuses, 'committed') >= 0;
			finish(s, committed ? 'partial' : 'failed',
				committed
					? 'Controller restarted or cluster deadline expired; committed batches cannot be rolled back automatically'
					: 'Cluster deadline expired; independent node watchdogs remain active');
			return;
		}
		if (a.phase == 'preflight') {
			if (index(statuses, 'failed') >= 0) {
				finish(s, 'failed', 'A node failed preflight');
				return;
			}
			if (!length(filter(statuses, (v) => v != 'ready'))) {
				a.phase = 'ready';
				save(s);
			}
			return;
		}
		if (a.phase == 'ready') return;
		if (a.phase == 'rolling_back') {
			advance_rollback(s);
			return;
		}
		if (index(statuses, 'failed') >= 0) {
			if (a.root.transaction_id && a.root.status != 'committed')
				try { io.local.rollback(a.root.transaction_id); } catch (e) {}
			for (let id in keys(a.nodes))
				if (index(['committed', 'rolled_back', 'no_change'], a.nodes[id].status) < 0)
					command(a, id, 'rollback');
			if (a.root.status == 'committed' || index(statuses, 'committed') >= 0)
				finish(s, 'partial', 'An AP failed after an earlier batch committed; review divergent versions');
			else {
				a.phase = 'rolling_back';
				a.failure = 'Node application failed';
				save(s);
			}
			return;
		}
		if (a.phase != 'applying') return;
		if (a.root_first && a.root.status != 'committed') {
			advance_root(s);
			return;
		}
		let changed = false;
		for (let id in keys(a.nodes)) {
			if (a.nodes[id].status != 'awaiting_confirm') continue;
			command(a, id, 'confirm');
			a.nodes[id].status = 'confirming';
			changed = true;
		}
		let in_flight = length(filter(values(a.nodes), (n) =>
			index(['applying', 'confirming'], n.status) >= 0));
		for (let id in keys(a.nodes)) {
			if (a.nodes[id].status != 'ready' || in_flight >= 2) continue;
			a.nodes[id].status = 'applying';
			command(a, id, 'apply');
			in_flight++;
			changed = true;
		}
		if (!length(filter(values(a.nodes), (n) => n.status != 'committed'))) {
			if (a.root.status != 'committed') advance_root(s);
			else finish(s, 'complete');
			return;
		}
		if (changed) save(s);
	}
	return { preflight, apply, rollback, peer, tick, repair, lifecycle };
}
