// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { effective_settings, settings_context } from './local_settings.uc';
import * as fs from 'fs';
import { acquire } from './locking.uc';
import { clone, equal } from './model.uc';
import { local_intent, node_peers } from './extended.uc';
import { require_lease } from './control_lease.uc';

export function serialized_repair(callback) {
	let lock = fs.open('/var/run/mesh-manager-repair-client.lock', 'a', 0600);
	if (!lock) die('storage_error: Manual repair lock unavailable');
	if (!acquire(lock)) { lock.close(); die('busy: Another manual repair request is in progress'); }
	try { let result = callback(); lock.close(); return result; }
	catch (e) { lock.close(); die(e.message || '' + e); }
}

export function repair_client(io) {
	function credentials() {
		return map(['device.key', 'device.crt', 'network-ca.crt'], (name) => io.read(name));
	}
	function same_confirmation_identity(data, frame) {
		if (equal(data, frame.data)) return true;
		// The ordinary agent may acknowledge the already persisted local phase
		// while the user confirmation probes Root. Only that derived receipt
		// update is benign: identity, reservation, settings and credentials still CAS.
		if (data?.agent?.status != frame.state?.active?.status ||
			!equal(data.agent.conflicts || [], frame.state.active.conflicts || [])) return false;
		let before = clone(frame.data), after = clone(data);
		delete before.agent.status; delete before.agent.conflicts;
		delete after.agent.status; delete after.agent.conflicts;
		return equal(before, after);
	}
	function current(frame, confirming) {
		let data = io.load('identity.json');
		if (!(confirming ? same_confirmation_identity(data, frame) : equal(data, frame.data)) || io.boot() != frame.boot ||
			!equal(credentials(), frame.credentials) || !equal(io.load('state.json'), frame.state))
			die('preview_changed: AP identity or local transaction changed while contacting the controller');
		return data;
	}
	function preview_current(frame, binding) {
		let actual = io.locked(() => ({ data: io.load('identity.json'), state: io.load('state.json'),
			credentials: credentials(), boot: io.boot(), now: io.now() }));
		if (!equal(actual.data, frame.data) || actual.boot != frame.boot ||
			!equal(actual.credentials, frame.credentials) || !equal(actual.state, frame.state))
			die('preview_changed: AP identity or local transaction changed while contacting the controller');
		let clock = io.now();
		if (actual.now < frame.now || clock < actual.now ||
			(binding && (binding.boot != actual.boot || clock >= binding.expires)))
			die('preview_changed: AP repair preview expired or its clock changed');
	}
	function target(frame, action, id, version, purpose) {
		let reply = io.request(frame.data, action, id, version, purpose);
		if (reply?.controller_id != frame.data.binding.controller_id ||
			reply.network_id != frame.data.binding.network_id)
			die('identity_error: Controller identity changed');
		return reply;
	}
	return (method, args) => io.serialized(() => {
		let settings = index(method, 'local_overrides_') == 0,
			preview_method = settings ? 'local_overrides_preview' : 'repair_preview',
			stage_method = settings ? 'local_overrides_stage' : 'repair_stage',
			confirm_method = settings ? 'local_overrides_confirm' : 'repair_confirm';
		if (index([preview_method, stage_method, confirm_method], method) < 0)
			die('invalid_method: Invalid manual repair method');
		let frame = io.locked(() => {
			let data = io.load('identity.json');
			if (data?.role == 'root') return { root: true, result: io.root(method, args) };
			if (data?.role != 'ap' || !data.binding)
				die('not_ap: Only an enrolled AP can restore controller configuration');
			if (method == confirm_method && (!data.agent?.repair || data.agent.transaction_id != args.transaction_id))
				die('invalid_state: Repair confirmation does not match the AP transaction');
			if (method == stage_method && args.takeover !== true)
				die('takeover_required: Explicit repair approval is required');
			if (method == preview_method) return { data, state: io.load('state.json'),
				credentials: credentials(), boot: io.boot(), now: io.now() };
			return { data: clone(data), state: clone(io.load('state.json')),
				credentials: credentials(), boot: io.boot() };
		});
		if (frame.root) return frame.result;
		let context;
		if (settings) {
			if (method == confirm_method) {
				if (frame.state?.active?.kind != 'overrides' || frame.state.active.id != args.transaction_id)
					die('invalid_state: Local settings confirmation does not match the transaction');
				if (frame.state.active.status == 'committed') return io.locked(() => { current(frame); return io.local.confirm(args.transaction_id); });
				if (!equal(frame.state.active.settings_context, { ...settings_context(frame.data, frame.state, frame.state.active.settings_context.record.values), root_version:frame.data.agent.version }))
					die('preview_changed: AP settings identity changed before confirmation');
			} else {
				if (!frame.state?.intent || frame.state.paused === true) die('mesh_disabled: Enable Mesh before editing local settings');
				context = settings_context(frame.data, frame.state, args.local);
			}
		}
		if (method == confirm_method) {
			if (!io.probe(frame.data.binding)) die('control_unavailable: Isolated controller health probe failed');
			target(frame, 'repair_check', frame.data.agent.transaction, frame.data.agent.version);
			return io.locked(() => {
				let data = current(frame, true), result = io.local.confirm(args.transaction_id);
				data.agent.status = result.status; data.cluster_version = data.agent.version;
				io.save('identity.json', data); return result;
			});
		}
		let reserved = false;
		try {
			let reply = target(frame, method == preview_method ? 'repair_intent' : 'repair_reserve',
				args.request_id, args.approval?.root_version, settings ? 'overrides' : 'repair');
			reserved = method == stage_method;
			if (type(reply.version) != 'int' || reply.version < 1)
				die('protocol_error: Invalid controller repair version');
			if (method == stage_method && reply.version != args.approval?.root_version)
				die('preview_changed: Controller intent version changed');
			let intent = local_intent(reply.intent, { ...(settings ? args.local : effective_settings(frame.data, frame.state)), peers: node_peers(frame.data.id,reply) },
				false, 'bridge', frame.data.id, require_lease(reply.control), frame.data.anchor || reply.anchor);
			if (context) context.root_version = reply.version;
			if (method == preview_method) {
				preview_current(frame);
				let plan = settings ? io.local.local_overrides_preview(intent, context) : io.local.repair_preview(intent);
				preview_current(frame, plan.binding);
				return { ...plan, root_version: reply.version };
			}
			return io.locked(() => {
				let data = current(frame);
				let approval = clone(args.approval); delete approval.root_version;
				let staged = settings ? io.local.local_overrides_stage(intent, args.request_id, true, approval, context) :
					io.local.repair_stage(intent, 'repair-' + args.request_id, true, approval);
				data.agent = { id: 'local-repair-' + args.request_id, transaction: args.request_id,
					version: reply.version, transaction_id: staged.id, status: staged.status,
					repair: true, local_settings: settings, mode: intent.backhaul.mode };
				try { io.save('identity.json', data); }
				catch (save_error) {
					try { io.local.rollback(staged.id); } catch (rollback_error) {}
					die(save_error.message);
				}
				return staged;
			});
		} catch (stage_error) {
			let message = stage_error.message;
			if (reserved) {
				// Release only this reservation through its original authenticated controller binding.
				try {
					let cancel = io.locked(() => {
						let data = io.load('identity.json'), active = io.load('state.json')?.active;
						return !(data?.agent?.repair && data.agent.transaction == args.request_id &&
							data.agent.transaction_id == active?.id &&
							index(['staged', 'apply_requested', 'applying', 'awaiting_confirm', 'committed'], active.status) >= 0);
					});
					if (cancel) {
						// A busy failure after reservation is not side-effect free: abort
						// closes this request. Do not invite automatic reuse of its ID.
						if (index(message || '', 'busy:') == 0)
							message = 'preview_changed: Controller reservation was cancelled; review a new preview';
						target(frame, 'repair_abort', args.request_id);
					}
				} catch (abort_error) {}
			}
			die(message);
		}
	});
}
