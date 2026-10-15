// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { run } from 'mesh_process';
import * as fs from 'fs';
import { random, read, load } from './durable.uc';
import { unseal } from './signed_response.uc';
import { private_address } from './identity.uc';
import { request_budget, control_health } from './protocol_worker.uc';
import { record_contact } from './controller_contact.uc';

const HANDOFF = {};
export function exchange(binding, request, enrollment, device, timeout_ms, record, authority) {
	if (!private_address(binding.address) || !match(binding.controller_id || '', /^[0-9a-f]{32}$/))
		die('identity_error: Invalid controller binding');
	let original = authority != null && authority === HANDOFF;
	if (authority != null && !original || original && (enrollment !== false ||
		request?.protocol !== 1 || request.action != 'handoff_check' ||
		!match(request.nonce || '', /^[0-9a-f]{32}$/) || type(record) != 'function'))
		die('invalid_request: Invalid private handoff exchange');
	// Never reuse a nonce supplied by a queued operation across transmissions.
	// Probes already own a nonce which is echoed by their dedicated response.
	if (!enrollment && request.action != 'probe' && !original) request = { ...request, nonce: random(16) };
	let budget = request_budget(request, enrollment), argv = [
		'/usr/libexec/mesh-manager-channel',
		budget.command,
		binding.address,
		'' + (enrollment ? 37902 : 37901),
		'/etc/mesh-manager/' + (enrollment ? 'join-ca.crt' : 'network-ca.crt'),
		enrollment ? '-' : '/etc/mesh-manager/device.crt',
		enrollment ? '-' : '/etc/mesh-manager/device.key',
		binding.controller_id
	];
	if (binding.controller_key!=null) push(argv,device || '-','key:'+binding.controller_key);
	else if (binding.controller_certificate!=null) push(argv,device || '-',binding.controller_certificate);
	else if (device) push(argv, device);
	if (timeout_ms != null && (type(timeout_ms) != 'int' || timeout_ms < 1))
		die('invalid_timeout: Peer exchange requires a positive finite budget');
	if (record != null && type(record) != 'function')
		die('invalid_request: Peer observation requires an internal callback');
	let timeout = timeout_ms == null ? budget.timeout : min(budget.timeout, timeout_ms);
	let result = run(argv, sprintf('%J', request), timeout),
		reply;
	if (result?.code != 0) die('peer_unavailable: Authenticated controller connection failed');
	try {
		reply = json(result.stdout);
	} catch (e) {
		die('protocol_error: Invalid controller response');
	}
	if (reply?.ok !== true)
		die((reply?.error?.code || 'peer_error') + ': Controller rejected request');
	let data = enrollment ? reply.data : unseal(binding, request, reply.data, { read, time });
	if (!enrollment && request.action!='probe') record_contact(binding);
	// Private first-configuration adapters retain the actual transmitted nonce
	// and signed bytes. No new public response fields or unsigned authority.
	if (record) record({ binding, request, reply: reply.data, device: device || null });
	return data;
}
// D creates a fresh nonce once for this finite health operation. Preserve that
// exact request for its signed receipt; ordinary retries still create new ones.
// The private object identity cannot be supplied by a public JSON request.
export function handoff_exchange(binding, request, device, timeout_ms, record) {
	return exchange(binding, request, false, device, timeout_ms, record, HANDOFF);
}
export function probe(binding, device) {
	let nonce = random(16),
		reply = exchange(
			device ? { ...binding, address: binding.control_address || '169.254.254.1' } : binding,
			{ protocol: 1, action: 'probe', network_id: binding.network_id, nonce },
			false,
			device
		);
	let verified = (
		reply?.nonce == nonce &&
		reply.controller_id == binding.controller_id &&
		reply.network_id == binding.network_id
	);
	if (verified) record_contact(binding);
	return verified;
}
export function probe_control(binding, device) {
	if (index(['mm-cw', 'mm-cm'], device) < 0)
		die('invalid_device: Probe must use a managed control interface');
	return probe(binding, device);
}
export function probe_management(binding) {
	return probe(binding, null);
}
export function probe_managed(binding) {
	return control_health({ available: device => fs.access('/sys/class/net/' + device), probe }, binding,load('identity.json'));
}
