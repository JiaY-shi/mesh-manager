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
export function control_route(io, binding) {
	for (let device in ['mm-cw', 'mm-cm']) {
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
export function control_health(io, binding) {
	let devices = filter(['mm-cw', 'mm-cm'], device => io.available(device));
	let bounded = { ...io, available: device => index(devices, device) >= 0 && io.available(device) };
	if (control_route(bounded, binding) != null) return true;
	return length(devices) == 1 && control_route(bounded, binding) != null;
}

// Only local durable lifecycle state may authorize the bootstrap/restore path.
// Missing interfaces or an unreachable Root never turn an enabled AP into an
// unconfigured one. A disabled AP must still report restoration and re-enable.
export function isolated_control_required(state, request) {
	let action = request?.action, active = state?.active;
	function assigned(intent) { return type(intent) == 'object' && index(keys(intent), 'control') >= 0; }
	if (action == 'mesh_abort' ||
		index(['mesh_intent', 'mesh_reserve'], action) >= 0 && request.enabled === false) return false;
	if (active?.kind == 'release' && active.mesh_enabled === false &&
		index(['applying', 'awaiting_confirm', 'rollback_requested', 'rolling_back', 'rollback_conflict'], active.status) >= 0 &&
		index(['poll', 'mesh_check'], action) >= 0) return false;
	if (active?.status == 'awaiting_confirm' && assigned(active.intent)) return true;
	return assigned(state?.intent) && state.paused !== true;
}

export function peer_router(io) {
	let cached;
	return (binding, request, context) => {
		let key = sprintf('%J', { binding, id: context?.id, role: context?.role,
			epoch: context?.enrollment?.epoch, control_required: context?.control_required === true, uplink: context?.overrides?.uplink,
			mesh_radio: context?.overrides?.mesh_radio, version: context?.cluster_version }),
			now = io.now(), route,
			cache_hit = cached?.key == key && cached.created <= now && cached.deadline > now &&
				(!cached.device || io.available(cached.device));
		if (cache_hit) {
			route = cached.device;
		} else {
			cached = null;
			route = control_route(io, binding);
		}
		if (!route && context?.control_required === true)
			die('control_unavailable: Isolated controller connection is unavailable');
		try {
			// A lost reply may follow a durable write; let the queued request retry on its next tick.
			let result = io.exchange(route ? { ...binding, address: '169.254.254.1' } : binding,
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
