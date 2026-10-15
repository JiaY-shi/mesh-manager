// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as crypto from 'mesh_crypto';
import {signer_statement,signer_epoch,public_signer} from './config_signing.uc';

const DOMAIN = 'mesh-manager/config-response/v1\n';
function fail() { die('signature_error: Invalid or expired signed controller response'); }
function identity(value) { return type(value) == 'string' && length(value) == 32 && match(value, /^[0-9a-f]{32}$/) != null; }
export function validate_request(request) {
	if (request?.action != 'probe' && !identity(request?.nonce)) fail();
}
function needed(request, data) {
	return request?.action != 'probe' && (request?.action != 'poll' ||
		data?.command != null || data?.intent != null || data?.authorization != null || data?.anchor_roster != null || data?.credentials != null || data?.signing_update != null || data?.ca != null);
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
	let state=io.load('cluster.json'),signer=public_signer(state,root.network_id);
	let body = sprintf('%J', {
		protocol: 1, schema: 1, network_id: root.network_id, controller_id: root.id,
		recipient, role: 'ap', key_epoch: signer?.epoch || 1, action: request.action, nonce: request.nonce,
		issued_at: now, expires_at: now + 120, data
	});
	if (length(body) > 60000) die('response_too_large: Signed controller response exceeds the channel limit');
	let cert = io.read('device.crt');
	if (crypto.certificate_identity(cert) != root.id) fail();
	let signature = crypto.message_sign(signer ? state.config_signing.key : io.read('device.key'), DOMAIN + body);
	if (type(signature) != 'string') fail();
	let result = { signed: { body, certificate: cert, signature } };
	if(signer)result.signed.signer={epoch:signer.epoch,key:signer.key,
		authorization:crypto.message_sign(io.read('device.key'),signer_statement(root.network_id,root.id,signer.epoch,signer.key))};
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
		type(proof) != 'object' || length(keys(proof)) != (proof.signer==null ? 3 : 4) ||
		type(proof.body) != 'string' || length(proof.body) > 60000) fail();
	let signer=proof.signer,pin=binding.signing?.network_id==binding.network_id ? binding.signing : null;
	if(signer!=null) {
		if(type(signer)!='object' || length(keys(signer))!=3 || !signer_epoch(signer.epoch) ||
			type(signer.key)!='string' || length(signer.key)>512 ||
			pin && (pin.epoch>signer.epoch || pin.epoch==signer.epoch && pin.key!=signer.key) ||
			!crypto.message_verify(io.read('network-ca.crt'),proof.certificate,binding.controller_id,
				signer_statement(binding.network_id,binding.controller_id,signer.epoch,signer.key),signer.authorization) ||
			!crypto.message_verify_key(signer.key,DOMAIN+proof.body,proof.signature))fail();
	} else if(!crypto.message_verify(io.read('network-ca.crt'),proof.certificate,
		binding.controller_id,DOMAIN+proof.body,proof.signature))fail();
	if(binding.controller_key!=null ? crypto.certificate_key_fingerprint(proof.certificate)!=binding.controller_key :
		binding.controller_certificate!=null && crypto.fingerprint(proof.certificate)!=binding.controller_certificate)fail();
	let envelope;
	try { envelope = json(proof.body); } catch (e) { fail(); }
	let now = io.time();
	if (type(envelope) != 'object' || length(keys(envelope)) != 12 ||
		sprintf('%J', envelope) != proof.body || envelope.protocol !== 1 || envelope.schema !== 1 ||
		envelope.network_id != binding.network_id || envelope.controller_id != binding.controller_id ||
		!identity(envelope.recipient) || envelope.recipient != crypto.certificate_identity(io.read('device.crt')) ||
		envelope.role != 'ap' || envelope.key_epoch !== (signer?.epoch || 1) ||
		!identity(request.nonce) || envelope.nonce != request.nonce || envelope.action != request.action ||
		type(now) != 'int' || now < 1704067200 || type(envelope.issued_at) != 'int' ||
		type(envelope.expires_at) != 'int' || envelope.expires_at != envelope.issued_at + 120 ||
		envelope.issued_at > now + 30 || envelope.expires_at <= now ||
		type(envelope.data) != 'object') fail();
	// A retired source no longer holds the transferred private signer. Its one
	// remaining device-key receipt is checked against the AP's exact committed
	// migration and a fresh new-Root proof by migration_client before use.
	if(!signer && pin) {
		if(request.action!='poll' || envelope.data.command?.action!='migration_switch' ||
			envelope.data.command.source!=binding.controller_id)fail();
		return {controller_id:envelope.data.controller_id,network_id:envelope.data.network_id,
			version:envelope.data.version,command:envelope.data.command};
	}
	if(signer && type(io.signer)=='function')io.signer({network_id:binding.network_id,epoch:signer.epoch,key:signer.key});
	// Nothing from the unsigned outer object may reach the transaction compiler.
	return envelope.data;
}
