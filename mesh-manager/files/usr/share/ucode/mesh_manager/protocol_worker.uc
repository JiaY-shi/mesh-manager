// SPDX-License-Identifier: GPL-2.0-only
'use strict';

export function request_budget(request, enrollment) {
	let probe = !enrollment && request?.action == 'probe';
	return { command: probe ? 'probe' : 'client', timeout: probe ? 4000 : 16000 };
}

export function decode_request(input, mode, budget) {
	if (type(input) != 'string' || !length(input) || length(input) > 65536 ||
		index(['node', 'enroll'], mode) < 0 || index(['api', 'probe'], budget) < 0)
		die('invalid_request: Invalid peer input');
	let request = json(input);
	if (budget == 'probe' && (mode != 'node' || type(request) != 'object' ||
		request.protocol != 1 || request.action != 'probe'))
		die('invalid_request: Probe frames cannot carry business requests');
	return request;
}

// A reachable business LAN is not evidence that the isolated management plane
// works. Callers explicitly decide whether bootstrap/restoration may use LAN.
export function control_route(io, binding, context) {
	let devices=context?.anchor!=null && context.id!=null && context.anchor.id==context.id ? ['br-mm-ctl'] : ['mm-cw','mm-cm'];
	for (let device in devices) {
		if (!io.available(device)) continue;
		let reachable;
		try { reachable = io.probe(binding, device); }
		catch (e) {
			if (index(e.message || '', 'peer_unavailable: ') != 0) die(e.message);
			continue;
		}
		if (reachable === true) return device;
	}
	return null;
}

// Explicit user confirmation may race a short reload interruption. Keep at
// most two read-only probes total: one per path, or one retry on the sole path.
// Background probes and routing budgets are unchanged. Never try the LAN.
export function control_health(io, binding, context) {
	let devices = filter(context?.anchor!=null && context.id!=null && context.anchor.id==context.id ? ['br-mm-ctl'] : ['mm-cw', 'mm-cm'], device => io.available(device));
	let bounded = { ...io, available: device => index(devices, device) >= 0 && io.available(device) };
	if (control_route(bounded, binding, context) != null) return true;
	return length(devices) == 1 && control_route(bounded, binding, context) != null;
}

// Only local durable lifecycle state may authorize the bootstrap/restore path.
// Missing interfaces or an unreachable Root never turn an enabled AP into an
// unconfigured one. A disabled AP must still report restoration and re-enable.
export function isolated_control_required(state, request) {
	let action = request?.action, active = state?.active;
	function assigned(intent) { return type(intent) == 'object' && (index(keys(intent), 'control') >= 0 || intent.anchor!=null); }
	if (action == 'mesh_abort' ||
		index(['mesh_intent', 'mesh_reserve'], action) >= 0 && request.enabled === false) return false;
	if (active?.kind == 'release' && active.mesh_enabled === false &&
		index(['applying', 'awaiting_confirm', 'rollback_requested', 'rolling_back', 'rollback_conflict'], active.status) >= 0 &&
		index(['poll', 'mesh_check'], action) >= 0) return false;
	if (active?.status == 'awaiting_confirm' && assigned(active.intent)) return true;
	return assigned(state?.intent) && state.paused !== true;
}

function committed_migration_poll(binding, request, context) {
	let m=context?.migration, receipt=request?.report?.migration, transaction=request?.report?.transaction,
		epoch=context?.authority_epoch ?? 1;
	function id(value) { return type(value)=='string' && length(value)==32 && match(value,/^[0-9a-f]{32}$/)!=null; }
	return context?.role==='ap' && id(context.id) && context.control_required===true &&
		request?.protocol===1 && request.action==='poll' && request.network_id===binding.network_id &&
		id(binding.controller_id) && id(binding.network_id) && type(epoch)=='int' && epoch>=1 &&
		(binding.epoch==null || binding.epoch===epoch) &&
		m?.phase==='committed' && m.metadata_committed===true && id(m.id) && id(m.transaction_id) &&
		m.source===binding.controller_id && id(m.target) && m.target!==m.source &&
		type(m.token)=='string' && length(m.token)==64 && match(m.token,/^[0-9a-f]{64}$/)!=null &&
		m.epoch===epoch+1 && m.binding?.epoch===m.epoch && m.binding.controller_id===m.target &&
		m.binding.network_id===binding.network_id && receipt?.protocol===1 && receipt.id===m.id &&
		receipt.phase==='committed' && receipt.epoch===m.epoch && receipt.transaction_id===m.transaction_id &&
		transaction?.id===m.transaction_id && transaction.request_id==='migration-'+m.id &&
		transaction.kind==='configure' && transaction.status==='committed' && transaction.mesh_enabled===null;
}

export function peer_router(io) {
	let cached;
	return (binding, request, context) => {
		// The source can already be a retiring AP, so an active-Root probe is
		// no longer a valid prerequisite for this exact committed continuation.
		// Send one pinned, nonce-signed poll on the reviewed wired control path;
		// migration_switch still verifies the new Root before changing binding.
		if (committed_migration_poll(binding,request,context)) {
			let device=context.anchor?.id===context.id ? 'br-mm-ctl' : 'mm-cw';
			if (!io.available(device)) die('control_unavailable: Reviewed migration wired connection is unavailable');
			return io.exchange({...binding,address:binding.control_address || '169.254.254.1'},request,false,device);
		}
		let key = sprintf('%J', { binding, id: context?.id, role: context?.role,
			epoch: context?.enrollment?.epoch, control_required: context?.control_required === true, uplink: context?.overrides?.uplink,
			mesh_radio: context?.overrides?.mesh_radio, version: context?.cluster_version, anchor:context?.anchor, authority_epoch:context?.authority_epoch }),
			now = io.now(), route,
			cache_hit = cached?.key == key && cached.created <= now && cached.deadline > now &&
				(!cached.device || io.available(cached.device));
		if (cache_hit) {
			route = cached.device;
		} else {
			cached = null;
			route = control_route(io, binding, context);
		}
		if (!route && context?.control_required === true)
			die('control_unavailable: Isolated controller connection is unavailable');
		try {
			// A lost reply may follow a durable write; let the queued request retry on its next tick.
			let result = io.exchange(route ? { ...binding, address: binding.control_address || '169.254.254.1' } : binding,
				request, false, route);
			if (!cache_hit) {
				let created = io.now();
				cached = created >= now ? { key, device: route, created, deadline: created + 10 } : null;
			}
			return result;
		} catch (e) {
			if (index(e.message || '', 'busy: ') != 0) cached = null;
			die(e.message);
		}
	};
}
