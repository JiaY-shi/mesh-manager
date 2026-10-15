// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as crypto from 'mesh_crypto';

const DOMAIN = 'mesh-manager/config-response/v1\n';
function fail() { die('signature_error: Invalid or expired signed controller response'); }
function identity(value) { return type(value) == 'string' && length(value) == 32 && match(value, /^[0-9a-f]{32}$/) != null; }
export function validate_request(request) {
	if (request?.action != 'probe' && !identity(request?.nonce)) fail();
}
function needed(request, data) {
	return request?.action != 'probe' && (request?.action != 'poll' ||
		data?.command != null || data?.intent != null || data?.authorization != null || data?.anchor_roster != null);
}

// io contains only local credentials and a clock; no persistence or shell process.
export function seal(request, data, recipient, io) {
	if (!needed(request, data)) return data;
	validate_request(request);
	let root = io.load('identity.json'), now = io.time();
	let retiring=root?.role=='ap' && root.migration && index(['switched','finishing','complete'],root.migration.phase)>=0 &&
		root.migration.source==root.id && request.action=='poll' && data?.command?.action=='migration_switch';
	if (root?.role != 'root' && !retiring || !identity(root.id) || !identity(root.network_id) ||
		!identity(recipient) || !identity(request?.nonce) || request.network_id != root.network_id ||
		type(request.action) != 'string' || type(now) != 'int' || now < 1704067200) fail();
	let body = sprintf('%J', {
		protocol: 1, schema: 1, network_id: root.network_id, controller_id: root.id,
		recipient, role: 'ap', key_epoch: 1, action: request.action, nonce: request.nonce,
		issued_at: now, expires_at: now + 120, data
	});
	if (length(body) > 60000) die('response_too_large: Signed controller response exceeds the channel limit');
	let cert = io.read('device.crt');
	if (crypto.certificate_identity(cert) != root.id) fail();
	let signature = crypto.message_sign(io.read('device.key'), DOMAIN + body);
	if (type(signature) != 'string') fail();
	let result = { signed: { body, certificate: cert, signature } };
	// Count the actual JSON frame, including escaped JSON and certificate PEM.
	if (length(sprintf('%J', { ok: true, data: result })) >= 65536)
		die('response_too_large: Signed controller response exceeds the channel limit');
	return result;
}

export function unseal(binding, request, response, io) {
	if (response?.signed == null) {
		if (needed(request, response)) fail();
		return response;
	}
	let proof = response.signed;
	if (type(response) != 'object' || length(keys(response)) != 1 ||
		type(proof) != 'object' || length(keys(proof)) != 3 ||
		type(proof.body) != 'string' || length(proof.body) > 60000 ||
		!crypto.message_verify(io.read('network-ca.crt'), proof.certificate,
			binding.controller_id, DOMAIN + proof.body, proof.signature)) fail();
	if(binding.controller_certificate!=null && crypto.fingerprint(proof.certificate)!=binding.controller_certificate)fail();
	let envelope;
	try { envelope = json(proof.body); } catch (e) { fail(); }
	let now = io.time();
	if (type(envelope) != 'object' || length(keys(envelope)) != 12 ||
		sprintf('%J', envelope) != proof.body || envelope.protocol !== 1 || envelope.schema !== 1 ||
		envelope.network_id != binding.network_id || envelope.controller_id != binding.controller_id ||
		!identity(envelope.recipient) || envelope.recipient != crypto.certificate_identity(io.read('device.crt')) ||
		envelope.role != 'ap' || envelope.key_epoch !== 1 ||
		!identity(request.nonce) || envelope.nonce != request.nonce || envelope.action != request.action ||
		type(now) != 'int' || now < 1704067200 || type(envelope.issued_at) != 'int' ||
		type(envelope.expires_at) != 'int' || envelope.expires_at != envelope.issued_at + 120 ||
		envelope.issued_at > now + 30 || envelope.expires_at <= now ||
		type(envelope.data) != 'object') fail();
	// Nothing from the unsigned outer object may reach the transaction compiler.
	return envelope.data;
}
