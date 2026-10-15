// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal, canonical, public_intent, public_op } from './model.uc';
import { compile, preview, value } from './compiler.uc';
import { identifier as managed_name, sha256 } from 'mesh_crypto';
import { HEALTH_MARGIN_SECONDS } from './reload.uc';
import { validate_controller_management, CONTROLLER_ADDRESS_MESSAGE } from './extended.uc';
import { steering_owned } from './roaming.uc';
import { validate_settings } from './local_settings.uc';
import { history_used, history_restored, clear_retained_history } from './history_retention.uc';
import { recovery_path } from './controller_loss.uc';
import { approved_radio_choices, committed_radio_choices } from './radio_planning.uc';

const TERMINAL = ['committed', 'rolled_back', 'rollback_conflict', 'expired'];
const STATES = [
	'staged',
	'apply_requested',
	'applying',
	'awaiting_confirm',
	'rollback_requested',
	'rolling_back',
	...TERMINAL
];
export function initial() {
	return { schema: 1, version: 0, intent: null, saved_intent: null, paused: false,
		owned: [], history: [], active: null };
}
function key(op) {
	return op.config + '.' + op.section + '.' + (op.option ?? '@section');
}
function matches(snapshot, op, side) {
	let section = snapshot[op.config]?.[op.section];
	return (
		(op.option == null || section?.type == op.type) && equal(value(snapshot, op) ?? null, op[side])
	);
}
function retired_interface(snapshot, op) {
	return op.config == 'wireless' && op.type == 'wifi-iface' && op.option == 'disabled' &&
		op.after == '1' && index(['explicit AP takeover', 'explicit legacy mesh takeover'], op.reason) >= 0 &&
		!snapshot.wireless?.[op.section];
}
export function owned_matches(snapshot, op) {
	// A removed legacy interface still satisfies the requirement to keep it inactive.
	if (retired_interface(snapshot, op)) return true;
	if (op.option != null || op.after == null) return matches(snapshot, op, 'after');
	let section = snapshot[op.config]?.[op.section];
	return section?.type == op.type && !length(filter(keys(op.after.values),
		(k) => !equal(section.values[k] ?? null, op.after.values[k])));
}
export function drift(state, snapshot) {
	return map(
		filter(state.owned, (op) => !owned_matches(snapshot, op)),
		(op) => ({
			config: op.config,
			section: op.section,
			option: op.option,
			message: 'Managed value changed outside Mesh Manager'
		})
	);
}

export function engine(io) {
	function state() {
		let s = io.load();
		if (s == null) return initial();
		function corrupt() {
			die('corrupt_state: Persistent journal is invalid; automatic takeover is disabled');
		}
		if (
			type(s) != 'object' ||
			s.schema != 1 ||
			type(s.version) != 'int' ||
			s.version < 0 ||
			type(s.owned) != 'array' ||
			type(s.history) != 'array' ||
			length(s.history) > 32
		)
			corrupt();
		if ('saved_steering_managed' in s && type(s.saved_steering_managed) != 'bool') corrupt();
		if (s.active?.local_confirmation != null && (s.active.local_confirmation !== true ||
			s.active.kind != 'release' || s.active.mesh_enabled !== false)) corrupt();
		if (s.active?.controller_lost != null && (s.active.controller_lost !== true ||
			s.active.local_confirmation !== true || type(s.active.preserved_conflicts) != 'array' ||
			length(s.active.preserved_conflicts) > 512)) corrupt();
		if (s.active?.local_confirmation === true && s.active.status == 'awaiting_confirm' &&
			(index(['int','double'],type(s.active.local_confirmation_after)) < 0 ||
				s.active.local_confirmation_after < s.active.created ||
				s.active.local_confirmation_after >= s.active.deadline)) corrupt();
		for (let conflict in s.active?.preserved_conflicts || [])
			if (type(conflict) != 'object' || !recovery_path(conflict.path) ||
				conflict.message != 'External change preserved; manual recovery required' ||
				!length(filter(s.owned,op=>key(op)==conflict.path)) && s.active.status != 'committed') corrupt();
		if (s.restore_checkpoint != null && (type(s.restore_checkpoint) != 'object' ||
			length(keys(s.restore_checkpoint)) != 4 || type(s.restore_checkpoint.id) != 'string' ||
			!match(s.restore_checkpoint.id,/^[a-zA-Z0-9_-]{1,96}$/) ||
			type(s.restore_checkpoint.request_id) != 'string' ||
			!match(s.restore_checkpoint.request_id || '', /^[a-zA-Z0-9_-]{16,96}$/) ||
			type(s.restore_checkpoint.version) != 'int' || s.restore_checkpoint.version < 1 ||
			type(s.restore_checkpoint.token) != 'string' ||
			!match(s.restore_checkpoint.token || '', /^[0-9a-f]{64}$/))) corrupt();
		if (s.active?.restore_recheck != null && (s.active.restore_recheck !== true || s.active.kind != 'release' ||
			s.active.mesh_enabled !== false || type(s.active.ops) != 'array' || length(s.active.ops) ||
			type(s.active.snapshot) != 'object')) corrupt();
		if (
			s.active != null &&
			(type(s.active) != 'object' ||
				type(s.active.ops) != 'array' ||
				index(STATES, s.active.status) < 0 ||
				type(s.active.id) != 'string' ||
				type(s.active.boot) != 'string' ||
				index(['configure', 'release', 'repair', 'overrides'], s.active.kind) < 0 ||
				(type(s.active.created) != 'int' && type(s.active.created) != 'double') ||
				type(s.active.conflicts) != 'array')
		)
			corrupt();
		if (s.local_settings) validate_settings(s.local_settings);
		if (s.active?.kind == 'overrides') validate_settings(s.active.settings_context?.record);
		if (s.active?.kind == 'repair' && (type(s.active.snapshot) != 'object' ||
			type(s.active.expected_owned) != 'array')) corrupt();
		if (
			s.active &&
			index(['applying', 'awaiting_confirm'], s.active.status) >= 0 &&
			type(s.active.deadline) != 'int' &&
			type(s.active.deadline) != 'double'
		)
			corrupt();
		for (let op in [...s.owned, ...(s.active?.ops || []), ...(s.active?.expected_owned || [])]) {
			if (
				type(op) != 'object' ||
				index(['network', 'wireless', 'dhcp', 'firewall', 'usteer'], op.config) < 0 ||
				!managed_name(op.section) ||
				type(op.type) != 'string' ||
				(op.option != null &&
					!managed_name(op.option))
			)
				corrupt();
			if (op.option == null)
				for (let side in ['before', 'after'])
					if (
						op[side] != null &&
						(type(op[side]) != 'object' ||
							type(op[side].type) != 'string' ||
							type(op[side].values) != 'object')
					)
						corrupt();
		}
		return s;
	}
	function save(s) {
		io.save(s);
	}
	function busy(s) {
		return s.active && index(TERMINAL, s.active.status) < 0;
	}
	function finish(s, status) {
		s.active.status = status;
		push(s.history, {
			id: s.active.id,
			request_id: s.active.request_id,
			status,
			version: s.version,
			kind: s.active.kind,
			failure: s.active.failure || null,
			conflicts: [...(s.active.conflicts || []), ...(s.active.preserved_conflicts || [])],
			...(s.active.controller_lost === true ? { cause:'controller_lost' } : {}),
			timestamp: io.wall()
		});
		if (length(s.history) > 32) {
			// Failed retries must not evict the one bounded committed restore fact.
			let proof=s.restore_checkpoint,oldest=0;
			while (oldest < length(s.history) - 1 && proof && s.history[oldest].id == proof.id &&
				s.history[oldest].request_id == proof.request_id && s.history[oldest].kind == 'release' &&
				s.history[oldest].status == 'committed' && s.history[oldest].version === proof.version) oldest++;
			s.history=[...slice(s.history,0,oldest),...slice(s.history,oldest+1)];
		}
		save(s);
	}
	function transaction(s, id) {
		if (type(id) != 'string' || !s.active || s.active.id != id)
			die('not_found: Transaction not found');
		return s.active;
	}
	function request_id(id) {
		if (type(id) != 'string' || !match(id, /^[a-zA-Z0-9_-]{16,96}$/))
			die('invalid_request: Request ID must contain 16 to 96 safe characters');
	}
	function public_active(a, operations) {
		if (!a) return null;
		return {
			id: a.id,
			request_id: a.request_id,
			status: a.status,
			kind: a.kind,
			...(a.restore_recheck === true ? {restore_recheck:true} : {}),
			...(a.kind == 'overrides' && operations !== false ? {
				local_settings: { before: clone(a.settings_context.before), after: clone(a.settings_context.record.values) }
			} : {}),
			mesh_enabled: a.mesh_enabled ?? null,
			failure: a.failure || null,
			conflicts: [...(a.conflicts || []), ...(a.preserved_conflicts || [])],
			...(a.local_confirmation === true ? {local_confirmation:true} : {}),
			...(a.controller_lost === true ? {cause:'controller_lost'} : {}),
			remaining: a.deadline != null && a.boot == io.boot() ? max(0, int(a.deadline - io.now())) : 0,
			ops: operations === false ? [] : map(a.ops, public_op)
		};
	}
	function restore_seal(checkpoint, snapshot) {
		// A private journal CAS digest, stable across loss of the tmpfs preview key.
		return sha256(sprintf('%J',canonical({kind:'restore_checkpoint',id:checkpoint.id,
			request_id:checkpoint.request_id,version:checkpoint.version,snapshot})));
	}
	function restore_proof(s, snapshot) {
		let proof=s.restore_checkpoint;
		if (s.paused !== true || s.intent != null || !s.saved_intent || length(s.owned) ||
			!proof || proof.version !== s.version || !history_restored(s, proof) ||
			restore_seal(proof,snapshot) != proof.token)
			die('ap_restore_unverified: The confirmed restoration and complete original snapshot cannot be verified');
	}
	function recovery_verified(s, snapshot) {
		let a=s.active;
		if (a?.status != 'committed' || length(a.conflicts || []) || length(a.preserved_conflicts || [])) return false;
		try {
			restore_proof(s,snapshot);
			return s.restore_checkpoint.id == a.id && s.restore_checkpoint.request_id == a.request_id &&
				!length(io.restore_checks?.(snapshot,[],s.saved_intent) || []);
		} catch(e) { return false; }
	}
	function status(view, deferred) {
		let s = state(),
			snapshot = io.snapshot();
		let compact = view && view != 'full' && s.active && index(TERMINAL, s.active.status) >= 0;
		let result = {
			phase: 1,
			version: s.version,
			intent: public_intent(s.intent),
			configured: !!(s.intent || s.saved_intent),
			mesh_enabled: !!s.intent && s.paused !== true,
			...(s.active?.controller_lost === true ? {controller_recovery:{cause:'controller_lost',
				request_id:s.active.request_id,transaction_id:s.active.id,status:s.active.status,
				health_confirmed:recovery_verified(s,snapshot),
				conflicts:[...s.active.conflicts,...(s.active.preserved_conflicts || [])]}} : {}),
			active: compact && index(['nodes', 'history', 'agent'], view) < 0
				? null : public_active(s.active, compact ? false : null),
			drift: drift(s, snapshot),
		};
		if (!view || view == 'full' || view == 'history') result.history = s.history;
		if (!view || index(['full','wireless','diagnostics'],view)>=0) result.steering_managed=steering_owned(s.owned);
		let active = s.active?.status == 'awaiting_confirm' ? s.active : null;
		// The runtime keeps this private frame in memory and samples ubus after releasing the lock.
		if (deferred === true) return { data: result, snapshot, active };
		result.capabilities = io.capabilities(snapshot, true);
		result.health = active ? io.health(active) : null;
		result.local = io.observe(snapshot, view);
		return result;
	}
	function reviewed(s, snapshot, intent, plan, kind, proof, context) {
		// JSON clients collapse 300.0 to 300; use a stable integral expiry in raw approval seals.
		let binding = proof || { boot: io.boot(), expires: int(io.now() + io.settings().candidate_timeout) };
		let token = io.seal({ kind, version: s.version, snapshot, intent, owned: s.owned,
			ops: plan.ops, settings_context: context || null, boot: binding.boot, expires: binding.expires });
		return { ...preview(plan), version: s.version, binding: { ...binding, token },
			...(plan.restore_recheck === true ? {restore_recheck:true} : {}),
			...(context ? { local_settings: { before: clone(context.before), after: clone(context.record.values) } } : {}) };
	}
	function check_approval(s, snapshot, intent, plan, kind, approval, context) {
		let proof = approval?.binding;
		if (type(proof) != 'object' || proof.boot != io.boot() ||
			(type(proof.expires) != 'int' && type(proof.expires) != 'double') ||
			proof.expires <= io.now() || proof.expires > io.now() + io.settings().candidate_timeout ||
			type(proof.token) != 'string' || !match(proof.token, /^[0-9a-f]{64}$/) ||
			!equal(approval, reviewed(s, snapshot, intent, plan, kind, proof, context)))
			die('preview_changed: Preview changed or expired; review and approve the new differences');
	}
	function candidate(intent, context) {
		if (context) validate_settings(context.record);
		let s = state(), snapshot = io.snapshot();
		let plan = compile(intent, snapshot, io.capabilities(snapshot, false, intent), s.owned);
		if (length(drift(s, snapshot)))
			push(plan.errors, {
				code: 'ownership_conflict',
				message: 'Resolve existing managed configuration drift before a new change'
			});
		if (s.paused === true) push(plan.errors, { code: 'mesh_disabled',
			message: 'Enable Mesh explicitly before applying managed configuration' });
		return reviewed(s, snapshot, intent, plan, context ? 'overrides' : 'configure', null, context);
	}
	function release_plan(s, snapshot, controller_lost) {
		if (!s.intent) {
			if (busy(s)) die('busy: Another transaction is active');
			let a=s.active;
			if (!a || index(['rolled_back','expired'],a.status) < 0 || length(a.conflicts) ||
				!(a.kind == 'configure' && a.mesh_enabled === true || a.kind == 'release' && a.restore_recheck === true))
				die('ap_restore_unverified: A complete unsuccessful re-enable journal is required to verify restoration');
			restore_proof(s,snapshot);
			if (!equal(snapshot,a.snapshot))
				die('ap_restore_unverified: The complete pre-enable configuration changed outside Mesh Manager');
			return {ops:[],errors:io.restore_checks?.(snapshot,[],s.saved_intent) || [],conflicts:[],dangerous:true,
				restore_recheck:true,warnings:['Verify the already restored configuration without changing it']};
		}
		let errors = [], ops = [], preserved_conflicts = [];
		for (let owner in reverse(clone(s.owned))) {
			if (retired_interface(snapshot, owner)) continue;
			if (!matches(snapshot, owner, 'after') && !matches(snapshot, owner, 'before')) {
				if (controller_lost === true) {
					push(preserved_conflicts, {path:key(owner),message:'External change preserved; manual recovery required'});
					// A newly managed AP/mesh section with an externally edited key
					// cannot be deleted. Stop its still-owned enable flag with field
					// CAS, preserving the key and all other external section values.
					let section=snapshot[owner.config]?.[owner.section];
					if (owner.config=='wireless' && owner.option==null && owner.before==null &&
						owner.after?.type=='wifi-iface' && section?.type=='wifi-iface' &&
						owner.after.values.disabled=='0' && section.values.disabled=='0')
						push(ops,{config:owner.config,section:owner.section,type:'wifi-iface',option:'disabled',
							before:'0',after:'1',changed:true,reason:'stop managed wireless while preserving external changes'});
					continue;
				}
				push(errors, { code: 'ownership_conflict',
					message: 'External settings must be reviewed before restoring ' + key(owner) });
				continue;
			}
			// An already restored value is retained and remains part of the raw approval.
			let current = clone(value(snapshot, owner) ?? null);
			push(ops, { ...owner, before: current, after: clone(owner.before),
				reason: 'restore original managed value', changed: !equal(current, owner.before) });
		}
		for (let error in io.restore_checks?.(snapshot, ops, s.intent) || []) push(errors, error);
		return { ops, errors, conflicts: [], ...(controller_lost === true ? {preserved_conflicts} : {}), dangerous: true,
			warnings: ['Only managed settings are restored; saved Mesh settings and identity are retained'] };
	}
	function mesh_preview(enabled, intent) {
		let s = state(), snapshot = io.snapshot();
		if (type(enabled) != 'bool') die('invalid_request: Mesh state must be a boolean');
		if (enabled) {
			if (s.paused !== true || !s.saved_intent) die('invalid_state: Mesh is not disabled');
			intent ||= s.saved_intent;
			let plan = compile(intent, snapshot, io.capabilities(snapshot, false, intent), s.owned, s.saved_steering_managed === true);
			return reviewed(s, snapshot, intent, plan, 'mesh_enable');
		}
		return reviewed(s, snapshot, null, release_plan(s, snapshot), 'mesh_disable');
	}
	function repair_plan(s, snapshot, intent) {
		if (!s.intent || !length(s.owned)) die('not_managed: This device is not managed');
		// Compile against the last managed baseline, then project onto confirmed ownership.
		let baseline = clone(snapshot);
		for (let op in s.owned) {
			if (op.option == null) {
				if (op.after == null) delete baseline[op.config]?.[op.section];
				else baseline[op.config][op.section] = clone(op.after);
			} else if (baseline[op.config]?.[op.section]?.type == op.type) {
				if (op.after == null) delete baseline[op.config][op.section].values[op.option];
				else baseline[op.config][op.section].values[op.option] = clone(op.after);
			}
		}
		let cap=io.capabilities(snapshot,false,intent), choices=committed_radio_choices(intent,cap,s.owned);
		if (choices==null) die('repair_scope_conflict: Committed radio ownership is invalid');
		let compiled = compile(intent, baseline, {...cap,approved_radio_choices:choices}, s.owned),
			errors = clone(compiled.errors), ops = [], expected_owned = clone(s.owned);
		function fail(op) {
			push(errors, { code: 'repair_scope_conflict',
				message: 'Managed section or ownership changed; manual review required at ' + key(op) });
		}
		for (let target in compiled.ops) {
			let owner = filter(expected_owned, (o) => key(o) == key(target))[0];
			if (!owner) { if (target.changed) fail(target); continue; }
			if (target.option == null && target.after && owner.after &&
				length(filter(keys(target.after.values), (k) => !(k in owner.after.values)))) {
				fail(target); continue;
			}
			owner.after = clone(target.after);
		}
		for (let owner in expected_owned) {
			let section = snapshot[owner.config]?.[owner.section];
			if (owner.option != null) {
				if (retired_interface(snapshot, owner)) continue;
				if (section?.type != owner.type) { fail(owner); continue; }
				push(ops, { ...owner, before: value(snapshot, owner) ?? null,
					reason: 'restore managed field', changed: !matches(snapshot, owner, 'after') });
			} else if (!section || owner.after == null) {
				if (section && owner.after == null) { fail(owner); continue; }
				push(ops, { ...owner, before: section ?? null,
					reason: 'restore managed section', changed: !matches(snapshot, owner, 'after') });
			} else if (section.type != owner.type) fail(owner);
			else {
				let previous = filter(s.owned, (o) => key(o) == key(owner))[0];
				for (let option in uniq([...keys(previous.after?.values || {}), ...keys(owner.after.values)])) {
					let before = section.values[option] ?? null, after = owner.after.values[option] ?? null;
					push(ops, { config: owner.config, section: owner.section, type: owner.type, option,
						before, after, reason: 'restore managed field', changed: !equal(before, after) });
				}
			}
		}
		return { errors, ops: length(errors) ? [] : ops, expected_owned, conflicts: [],
			warnings: ['Only managed fields are restored; other settings are preserved',
				'Rollback restores the values present before this repair'], dangerous: true };
	}
	function repair_preview(intent) {
		let s = state(), snapshot = io.snapshot(), plan = repair_plan(s, snapshot, intent);
		let result = reviewed(s, snapshot, intent, plan, 'repair');
		delete result.expected_owned;
		return result;
	}
	function repair_stage(intent, id, takeover, approval) {
		request_id(id);
		let s = state();
		if (s.active?.request_id == id) {
			if (s.active.kind != 'repair' || !equal(s.active.intent, intent))
				die('request_reused: Request ID belongs to a different candidate');
			return public_active(s.active);
		}
		if (history_used(s, 'local', id))
			die('request_reused: Request ID has already completed');
		if (busy(s)) die('busy: Another transaction is active');
		if (takeover !== true) die('takeover_required: Explicit repair approval is required');
		let snapshot = io.snapshot(), plan = repair_plan(s, snapshot, intent), reviewed_plan = clone(plan);
		delete reviewed_plan.expected_owned;
		if (length(plan.errors)) die('preflight_failed: Repair requires manual review');
		check_approval(s, snapshot, intent, reviewed_plan, 'repair', approval);
		s.active = { id: io.id(), request_id: id, kind: 'repair', intent: clone(intent),
			status: 'staged', ops: plan.ops, expected_owned: plan.expected_owned,
			snapshot, boot: io.boot(), created: io.now(), deadline: null, conflicts: [] };
		save(s);
		return public_active(s.active);
	}
	function stage(intent, id, takeover, release, approval, mesh_enabled, context) {
		if (context) validate_settings(context.record);
		let kind = context ? 'overrides' : release ? 'release' : 'configure';
		request_id(id);
		let s = state();
		if (s.active?.request_id == id) {
			if (!equal(s.active.intent, intent) || s.active.kind != kind || !equal(s.active.settings_context || null, context || null) ||
				(s.active.mesh_enabled ?? null) != (mesh_enabled ?? null))
				die('request_reused: Request ID belongs to a different candidate');
			return public_active(s.active);
		}
		if (history_used(s, 'local', id))
			die('request_reused: Request ID has already completed');
		if (busy(s)) die('busy: Another transaction is active');
		if (takeover !== true) die('takeover_required: Explicit takeover approval is required');
		if (!release && s.paused === true && mesh_enabled !== true)
			die('mesh_disabled: Mesh must be enabled explicitly');
		let snapshot = io.snapshot(),
			plan;
		if (length(filter(s.owned, (op) => !owned_matches(snapshot, op) &&
			(!release || !matches(snapshot, op, 'before')))))
			die('ownership_conflict: Managed fields have external changes');
		if (release) {
			plan = release_plan(s, snapshot);
		} else {
			let choices=approved_radio_choices(approval?.ops);
			if (choices==null) die('preview_changed: Approved radio choices are invalid');
			let cap=io.capabilities(snapshot,false,intent);
			plan = compile(intent, snapshot, {...cap,approved_radio_choices:choices}, s.owned,
				mesh_enabled === true && s.saved_steering_managed === true);
		}
		if (length(plan.errors))
			die(
				'preflight_failed: ' +
					join(
						'; ',
						map(plan.errors, (e) => e.message)
					)
			);
		check_approval(s, snapshot, intent, plan,
			mesh_enabled === true ? 'mesh_enable' : release ? 'mesh_disable' : kind, approval, context);
		s.active = {
			id: io.id(),
			request_id: id,
			intent: clone(intent),
			kind,
			...(plan.restore_recheck === true ? {restore_recheck:true} : {}),
			...(context ? { settings_context: clone(context) } : {}),
			mesh_enabled: release ? false : mesh_enabled ?? null,
			status: 'staged',
			ops: plan.ops,
			snapshot,
			boot: io.boot(),
			created: io.now(),
			deadline: null,
			conflicts: []
		};
		save(s);
		return public_active(s.active);
	}
	function apply(id) {
		let s = state(),
			a = transaction(s, id);
		if (a.status == 'staged') {
			a.status = 'apply_requested';
			save(s);
		} else if (
			index(['apply_requested', 'applying', 'awaiting_confirm', 'committed'], a.status) < 0
		)
			die('invalid_state: Candidate cannot be applied');
		return public_active(a);
	}
	function confirm(id) {
		let s = state(),
			a = transaction(s, id);
		if (a.status == 'committed') return public_active(a);
		if (a.status != 'awaiting_confirm' || a.boot != io.boot() || io.now() >= a.deadline)
			die('invalid_state: Transaction is not awaiting confirmation or has expired');
		let snapshot = io.snapshot();
		if (a.local_confirmation === true && io.capabilities(snapshot,true).controller_identity?.role != 'ap')
			die('identity_error: AP restoration identity changed');
		if (a.restore_recheck === true) {
			restore_proof(s,snapshot);
			if (!equal(snapshot,a.snapshot))
				die('configuration_conflict: The already restored configuration changed');
		}
		function restore_safe() {
			if (a.kind == 'release' && length(io.restore_checks?.(snapshot,a.ops,
				a.restore_recheck === true ? s.saved_intent : s.intent) || []))
				die('restore_unsafe: Restore wiring or DHCP safety changed during confirmation');
		}
		restore_safe();
		let untouched = filter(
			s.owned,
			(op) => !length(filter(a.ops, (changed) => key(changed) == key(op))) &&
				!length(filter(a.preserved_conflicts || [], conflict => conflict.path == key(op)))
		);
		let health = io.health(a);
		if (!health.ok) {
			let failed = map(filter(health.checks || [], c => !c.ok && managed_name(c.name)), c => c.name);
			die('unhealthy: Management health checks have not passed' +
				(length(failed) ? ': ' + join(', ', slice(failed, 0, 16)) : ''));
		}
		let mismatched = a.kind == 'repair'
			? filter(a.expected_owned, (op) => !owned_matches(snapshot, op))
			: [...filter(a.ops, (op) => !matches(snapshot, op, 'after')),
				...filter(untouched, (op) => !matches(snapshot, op, 'after') && !retired_interface(snapshot, op))];
		if (length(mismatched))
			die('configuration_conflict: Managed field differs at ' + key(mismatched[0]));
		restore_safe();
		if (!equal(io.snapshot(),snapshot))
			die('configuration_conflict: Configuration changed during health verification');
		if (a.boot != io.boot() || io.now() >= a.deadline)
			die('invalid_state: Transaction expired during confirmation checks');
		if (a.kind == 'release') {
			if (a.restore_recheck !== true) {
				s.saved_intent = clone(s.intent);
				s.saved_steering_managed = steering_owned(s.owned);
			}
			s.paused = true;
			s.owned = [];
			s.intent = null;
		} else if (a.kind == 'repair') {
			s.owned = clone(a.expected_owned);
			s.intent = clone(a.intent);
		} else {
			for (let op in a.ops) {
				let old = filter(s.owned, (o) => key(o) == key(op))[0];
				if (old) old.after = clone(op.after);
				else push(s.owned, clone(op));
			}
			s.intent = clone(a.intent);
		}
		if (a.kind != 'release') { s.paused = false; s.saved_intent = clone(s.intent); }
		// Settings and ownership commit in the same durable journal write.
		if (a.kind == 'overrides') s.local_settings = clone(a.settings_context.record);
		s.version++;
		if (a.kind == 'release') {
			let checkpoint={id:a.id,request_id:a.request_id,version:s.version};
			s.restore_checkpoint={...checkpoint,token:restore_seal(checkpoint,snapshot)};
		} else delete s.restore_checkpoint;
		finish(s, 'committed');
		return public_active(a);
	}
	function rollback(id) {
		let s = state(),
			a = transaction(s, id);
		if (index(['rolled_back', 'rollback_conflict'], a.status) >= 0) return public_active(a);
		if (!busy(s)) die('invalid_state: Confirmed/expired transactions cannot be rolled back');
		if (a.status == 'staged' || a.status == 'apply_requested') finish(s, 'rolled_back');
		else {
			a.status = 'rollback_requested';
			save(s);
		}
		return public_active(a);
	}
	function restore(s) {
		let a = s.active;
		a.status = 'rolling_back';
		save(s);
		let restore_ops = [],
			snapshot = io.snapshot();
		for (let op in reverse(clone(a.ops))) {
			if (matches(snapshot, op, 'before')) continue;
			if (matches(snapshot, op, 'after'))
				push(restore_ops, { ...op, before: op.after, after: op.before });
			else if (!length(filter(a.conflicts, (c) => c.path == key(op))))
				push(a.conflicts, {
					path: key(op),
					message: 'External change preserved; manual recovery required'
				});
		}
		// A failed write/reload remains recoverable instead of prematurely marking rollback done.
		if (length(restore_ops)) io.write(restore_ops);
		let changed = filter(a.ops, (op) => !equal(op.before, op.after));
		if (length(changed)) io.reload(changed);
		finish(s, length(a.conflicts) ? 'rollback_conflict' : 'rolled_back');
	}
	function tick() {
		let s = state(),
			a = s.active;
		if (!busy(s)) return;
		if (a.status == 'staged') {
			if (a.boot != io.boot() || io.now() - a.created >= io.settings().candidate_timeout)
				finish(s, 'expired');
			return;
		}
		if (
			index(['applying', 'awaiting_confirm'], a.status) >= 0 &&
			(a.boot != io.boot() || io.now() >= a.deadline)
		) {
			a.failure = a.boot != io.boot() ? 'Device rebooted before confirmation' : 'Confirmation timed out';
			// Sample once at expiry, never on every recovery tick or flash write.
			// Publish fixed health names only; arbitrary adapter text may contain secrets.
			if (a.boot == io.boot() && a.status == 'awaiting_confirm') {
				try {
					let failed = map(filter(io.health(a)?.checks || [], c => c.ok !== true &&
						(index(['management_interface', 'management_protocol', 'management_address',
							'expected_configuration', 'wan_interface', 'backhaul_mesh', 'backhaul_peer_acl',
                            'guest_interface','guest_single_uplink','guest_dhcp'], c.name) >= 0 ||
							type(c.name) == 'string' && length(c.name) <= 64 && match(c.name, /^(ap|guest_ap)_radio[0-9]+$/))), c => c.name);
					if (length(failed)) a.failure += ': ' + join(', ', slice(failed, 0, 16));
				} catch (e) {}
			}
			a.status = 'rollback_requested';
			save(s);
		}
		// Recover applying after a process crash, even when the original deadline has not passed.
		if (a.status == 'applying') {
			a.failure = 'Interrupted application';
			a.status = 'rollback_requested';
			save(s);
		}
		if (index(['rollback_requested', 'rolling_back'], a.status) >= 0) {
			restore(s);
			return;
		}
		if (a.status == 'awaiting_confirm' && a.local_confirmation === true &&
			io.now() >= a.local_confirmation_after) {
			try { confirm(a.id); }
			catch (e) {
				// Health can still be settling. The original deadline and independent
				// CAS rollback remain authoritative; no network wait extends them.
				if (index(e.message || '', 'unhealthy:') != 0) die(e.message || ''+e);
			}
			return;
		}
		if (a.status != 'apply_requested') return;
		if (a.boot != io.boot() || io.now() - a.created >= io.settings().candidate_timeout) {
			finish(s, 'expired');
			return;
		}
		let snapshot = io.snapshot();
		if (a.restore_recheck === true) {
			try { restore_proof(s,snapshot); }
			catch (e) { a.failure='ap_restore_unverified: Confirmed restoration snapshot changed'; finish(s,'rolled_back'); return; }
		}
		if (a.kind == 'release' && length(io.restore_checks?.(snapshot, a.ops,
			a.restore_recheck === true ? s.saved_intent : s.intent) || [])) {
			a.failure = 'restore_unsafe: Restore wiring or DHCP preflight changed';
			finish(s, 'rolled_back');
			return;
		}
		// Apply checks only live UCI pending state and the current controller identity.
		// Wireless support was freshly compiled at preview/stage; the advisory fields
		// returned here do not authorize a write or extend the recovery deadline.
		let current_capabilities = io.capabilities(snapshot, true);
		if (
			(a.snapshot && !equal(snapshot, a.snapshot)) ||
			length(filter(a.ops, (op) => !matches(snapshot, op, 'before'))) ||
			current_capabilities.pending_changes
		) {
			a.failure = 'Configuration changed after preflight';
			finish(s, 'rolled_back');
			return;
		}
		if (a.kind != 'release' && current_capabilities.controller_identity?.role == 'root') {
			try { validate_controller_management({ management: a.intent?.management }, current_capabilities.controller_identity.address); }
			catch (e) {
				a.failure = 'controller_address_unsupported: ' + CONTROLLER_ADDRESS_MESSAGE;
				finish(s, 'rolled_back');
				return;
			}
		}
		a.status = 'applying';
		a.deadline = io.now() + io.settings().confirmation_timeout;
		save(s);
		try {
			function confirmation_budget() {
				if (a.boot != io.boot() || io.now() + HEALTH_MARGIN_SECONDS > a.deadline)
					die('reload_error: Confirmation budget exhausted');
			}
			confirmation_budget();
			let changed = filter(a.ops, (op) => !equal(op.before, op.after));
			if (length(changed)) {
				io.write(changed);
				confirmation_budget();
				io.reload(changed, a.deadline);
			}
			confirmation_budget();
			a.status = 'awaiting_confirm';
			if (a.local_confirmation === true) a.local_confirmation_after = min(io.now() + 10, a.deadline - 1);
			save(s);
			confirmation_budget();
		} catch (e) {
			let reload_errors = ['reload_error: Local ubus connection unavailable',
				'reload_error: Local service request failed: network.reload',
				'reload_error: Confirmation budget exhausted', 'reload_error: Reload budget exhausted',
				...map(['dnsmasq', 'odhcpd', 'firewall', 'usteer'],
					name => 'reload_error: Cannot reload ' + name)];
			a.failure = index(reload_errors, e.message) >= 0
				? e.message : 'Configuration apply or reload failed';
			a.status = 'rollback_requested';
			save(s);
			restore(s);
		}
	}
	return {
		status,
		// Private adapters only: no RPC method exposes these operations. The first
		// caller has a verified Root reservation/command; the second is the local
		// five-minute recovery policy checked by the independent daemon.
		authorize_restoration: (id, request) => {
			let s=state(),a=transaction(s,id);
			if (a.request_id != request || a.kind != 'release' || a.mesh_enabled !== false ||
				index(['staged','apply_requested'],a.status) < 0 ||
				io.capabilities(io.snapshot(),true).controller_identity?.role != 'ap')
				die('invalid_state: Only an approved AP restoration may use local health confirmation');
			if (a.local_confirmation !== true) {a.local_confirmation=true;save(s);}
			return public_active(a);
		},
		controller_lost_stage: request => {
			request_id(request);let s=state();
			if (s.active?.request_id == request && s.active.controller_lost === true) return public_active(s.active);
			if (busy(s)) die('busy: Finish independent transaction recovery first');
			if (!s.intent || s.paused === true) die('mesh_disabled: Mesh is already disabled');
			let snapshot=io.snapshot(),cap=io.capabilities(snapshot,true);
			if (cap.controller_identity?.role != 'ap') die('not_ap: Controller loss recovery is limited to AP nodes');
			if (cap.pending_changes) die('pending_changes: Resolve pending UCI edits before restoring');
			let plan=release_plan(s,snapshot,true);
			if (length(plan.errors)) die('restore_unsafe: Original LAN or DHCP cannot be restored safely');
			s.active={id:io.id(),request_id:request,kind:'release',intent:null,mesh_enabled:false,
				controller_lost:true,local_confirmation:true,status:'staged',ops:plan.ops,snapshot,
				preserved_conflicts:plan.preserved_conflicts,conflicts:[],boot:io.boot(),created:io.now(),deadline:null};
			save(s);return public_active(s.active);
		},
		restoration_committed: (id, request) => {
			let s=state(),a=s.active;
			if (a?.id != id || a.request_id != request || a.kind != 'release' || a.mesh_enabled !== false ||
				a.status != 'committed' || length(a.preserved_conflicts || [])) return null;
			let snapshot=io.snapshot();restore_proof(s,snapshot);
			if (s.restore_checkpoint.id != id || s.restore_checkpoint.request_id != request ||
				length(io.restore_checks?.(snapshot,[],s.saved_intent) || []))
				die('ap_restore_unverified: Committed restoration no longer matches its original configuration or safe wiring');
			return {id:a.id,request_id:a.request_id,version:s.version};
		},
		recovery_pending: () => !!busy(state()),
		history: () => clone(state().history),
		clear_history: args => {
			if (args.group != 'local') die('invalid_request: Expected local history');
			let s=state(), result=clear_retained_history(s,args,io.boot());
			if (result.cleared && !result.replayed) save(s);
			return result;
		},
		preview: candidate,
		local_overrides_preview: (intent, context) => candidate(intent, context),
		local_overrides_stage: (intent, id, takeover, approval, context) => stage(intent, id, takeover, false, approval, null, context),
		repair_preview,
		repair_stage,
		mesh_preview,
		mesh_stage: (enabled, intent, id, takeover, approval) => {
			if (enabled !== true && enabled !== false) die('invalid_request: Mesh state must be a boolean');
			let s = state();
			if (enabled && (s.paused !== true || !s.saved_intent) && s.active?.request_id != id)
				die('invalid_state: Mesh is not disabled');
			return stage(enabled ? intent || s.saved_intent : null, id, takeover, !enabled, approval, enabled);
		},
		stage: (intent, id, takeover, approval) => stage(intent, id, takeover, false, approval),
		apply,
		confirm,
		rollback,
		release: (id, takeover, approval) => stage(null, id, takeover, true, approval, false),
		tick
	};
}
