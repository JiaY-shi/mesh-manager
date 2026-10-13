// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as crypto from 'mesh_crypto';
import { canonical, clone, equal } from './model.uc';
import { private_address, public_identity } from './identity.uc';
import { reference_approval, reference_transport } from './handoff_reference.uc';

// Original joining authority is durable. Only external I/O runs unlocked; a
// late reply never becomes authority for different raw credentials or owners.
const FILES = ['identity.json', 'device.key', 'join-ca.crt', 'network-ca.crt',
	'device.crt', 'state.json', 'cluster.json'];
const ATTEMPT = 50; // Exchange16 + one actor permit8 + four durable5 + local6.

function hash_value(value) {
	return type(value) == 'string' && match(value, /^[0-9a-f]{64}$/) != null;
}
function digest(raw) {
	if (raw == null) return null;
	if (type(raw) != 'string') die('identity_error: Joining raw digest input is invalid');
	let value = crypto.sha256(raw);
	if (!hash_value(value)) die('identity_error: Joining raw digest is unavailable');
	return value;
}
function clock_value(value) {
	return index(['int', 'double'], type(value)) >= 0 && value >= 0 && value < 9007199254740991;
}
function base_identity(data) {
	let base = clone(data);
	delete base.joining.approval;
	return sprintf('%J', base);
}
function approval_scope(data, raw) {
	let scope = { scope: digest(base_identity(data)), key: digest(raw['device.key']),
		join_ca: digest(raw['join-ca.crt']) };
	if (!hash_value(scope.scope) || !hash_value(scope.key) || !hash_value(scope.join_ca))
		die('identity_error: Joining approval scope is unavailable');
	return scope;
}
function checkpoint_proof(checkpoint, key) {
	let value = clone(checkpoint);
	delete value.proof;
	// The proof key is not the stored raw-key digest and is never persisted.
	let proof = crypto.hmac(digest('mesh-manager-join-approval-v1\n' + key), sprintf('%J', canonical(value)));
	if (!hash_value(proof)) die('identity_error: Joining approval proof is unavailable');
	return proof;
}
function expected_identity(data, v) {
	let result = clone(data);
	let handoff = data.joining?.approval?.handoff;
	result.binding = { address: v.address, controller_id: v.controller_id,
		network_id: v.network_id, port: v.port, ca_fingerprint: v.fingerprint };
	result.network_id = v.network_id; result.role = 'ap'; result.joining = null;
	if (handoff != null) result.handoff = clone(handoff);
	return result;
}
function checkpoint_fields(value) {
	if (type(value) != 'object') return false;
	let names = ['schema','scope','key','join_ca','before_ca','before_cert','cert','proof'];
	if (value.handoff != null) push(names,'handoff');
	return equal(sort(keys(value)),sort(names));
}
function validate_checkpoint(data, raw, permitted_ref) {
	let checkpoint = data.joining.approval;
	if (checkpoint == null) return;
	let scope = approval_scope(data, raw);
	if (!checkpoint_fields(checkpoint) || checkpoint.schema !== 1 || checkpoint.scope !== scope.scope ||
		checkpoint.key !== scope.key || checkpoint.join_ca !== scope.join_ca ||
		type(checkpoint.proof) != 'string' || !match(checkpoint.proof, /^[0-9a-f]{64}$/) ||
		!crypto.constant_equal(checkpoint.proof, checkpoint_proof(checkpoint, raw['device.key'])) ||
		raw['identity.json'] !== sprintf('%J', data) ||
		type(checkpoint.cert) != 'string' || !length(checkpoint.cert) || length(checkpoint.cert) > 16384 ||
		(checkpoint.before_ca != null && type(checkpoint.before_ca) != 'string') ||
		(checkpoint.before_cert != null && type(checkpoint.before_cert) != 'string') ||
		(checkpoint.before_ca != null && !match(checkpoint.before_ca, /^[0-9a-f]{64}$/)) ||
		(checkpoint.before_cert != null && !match(checkpoint.before_cert, /^[0-9a-f]{64}$/)) ||
		index([checkpoint.before_ca, digest(data.joining.invitation.ca)], digest(raw['network-ca.crt'])) < 0 ||
		index([checkpoint.before_cert, digest(checkpoint.cert)], digest(raw['device.crt'])) < 0 ||
		(digest(raw['device.crt']) != checkpoint.before_cert &&
			raw['network-ca.crt'] !== data.joining.invitation.ca))
		die('identity_error: Joining credential checkpoint no longer matches');
	let reference_scope = { identity: raw['identity.json'],
		key: raw['device.key'], join_ca: raw['join-ca.crt'], network_ca: raw['network-ca.crt'],
		cert: raw['device.crt'], state: raw['state.json'], snapshot: raw.snapshot };
	if (checkpoint.handoff != null && !(permitted_ref == null
		? reference_approval(reference_scope, checkpoint, base_identity(data))
		: reference_transport(reference_scope, checkpoint, base_identity(data), permitted_ref)))
		die('identity_error: Original initial handoff baseline changed');
}

// Private actor/worker authority verification. No I/O, clock or durable writes;
// the caller independently fences boot, origin session and transport ownership.
// The optional original is the exact pre-checkpoint identity serialization,
// needed only to prove the final AP identity after joining has been removed.
function approval(scope, checkpoint, original, permitted_ref) {
	try {
		if (type(scope) != 'object' || type(scope.identity) != 'string' ||
			type(scope.key) != 'string' || type(scope.join_ca) != 'string') return null;
		if (checkpoint?.handoff != null && permitted_ref == null &&
			(!('state' in scope) || !('snapshot' in scope))) return null;
		let current = json(scope.identity), data = current;
		if (original != null) {
			if (type(original) != 'string') return null;
			data = json(original);
			if (original !== sprintf('%J', data) || data?.joining?.approval != null) return null;
			data.joining.approval = clone(checkpoint);
		} else if (!equal(data?.joining?.approval, checkpoint)) return null;
		let j = data?.joining, v = j?.invitation, hash = crypto.key_fingerprint(scope.key);
		if (data?.schema !== 1 || data.role != 'unbound' || data.binding || !hash ||
			data.id != substr(hash, 0, 32) || data.fingerprint != hash ||
			index(['requesting', 'pending'], j?.status) < 0 ||
			!match(j.request_id || '', /^[0-9a-f]{32}$/) || !match(j.secret || '', /^[0-9a-f]{64}$/) ||
			type(v) != 'object' || v.protocol != 1 || !private_address(v.address) ||
			!match(v.controller_id || '', /^[0-9a-f]{32}$/) || v.controller_id == data.id ||
			!match(v.network_id || '', /^[0-9a-f]{32}$/) || !match(v.token || '', /^[0-9a-f]{64}$/) ||
			!match(v.fingerprint || '', /^[0-9a-f]{64}$/) || type(v.ca) != 'string' || length(v.ca) > 4096 ||
			v.port != 37901 || v.enroll_port != 37902 || type(v.name) != 'string' || length(v.name) > 64 ||
			crypto.fingerprint(v.ca) != v.fingerprint || crypto.normalize_cert(v.ca) !== v.ca ||
			scope.join_ca !== v.ca || checkpoint == null) return null;
		let raw = { 'identity.json': sprintf('%J', data), 'device.key': scope.key,
			'join-ca.crt': scope.join_ca, 'network-ca.crt': scope.network_ca, 'device.crt': scope.cert,
			'state.json': scope.state, snapshot: scope.snapshot };
		if (original == null && raw['identity.json'] !== scope.identity) return null;
		validate_checkpoint(data, raw, permitted_ref);
		if (!crypto.verify_leaf(v.ca, checkpoint.cert, scope.key, data.id)) return null;
		let base = base_identity(data), expected = sprintf('%J', expected_identity(data, v));
		let stage = scope.cert === checkpoint.cert ? 'leaf' : scope.network_ca === v.ca ? 'ca' : 'approval';
		if (original != null) {
			if (scope.identity !== expected || scope.network_ca !== v.ca || scope.cert !== checkpoint.cert) return null;
			stage = 'ap';
		}
		return { stage, base_identity: base, expected_identity: expected,
			ca: v.ca, cert: checkpoint.cert, checkpoint: clone(checkpoint) };
	} catch (e) { return null; }
}

export function approval_valid(scope,checkpoint,original) { return approval(scope,checkpoint,original); }
export function approval_transport_valid(scope,checkpoint,original,permitted_ref) {
	if (checkpoint?.handoff == null || permitted_ref == null) return null;
	return approval(scope,checkpoint,original,permitted_ref);
}

export function approval_prepare(scope, checkpoint) {
	try {
		if (type(scope) != 'object' || type(scope.identity) != 'string') return null;
		let data = json(scope.identity);
		if (scope.identity !== sprintf('%J', data) || type(data?.joining) != 'object') return null;
		if (data.joining.approval != null) return approval_valid(scope, checkpoint);
		data.joining.approval = clone(checkpoint);
		return approval_valid({ ...scope, identity: sprintf('%J', data) }, checkpoint);
	} catch (e) { return null; }
}

export function joining_exchange(io, validate_invitation) {
	function require_adapter() {
		if (type(io.locked) != 'function' || type(io.join_transport) != 'function' ||
			type(io.join_exchange) != 'function')
			die('runtime_unavailable: Joining exchange adapter is unavailable');
	}
	function raw_files() {
		let raw = {};
		for (let name in FILES) raw[name] = io.read(name);
		return raw;
	}
	function initial_wireless(data) {
		let e = data?.enrollment;
		return data?.joining?.approval?.handoff != null || e?.enabled === true && e.phase == 'wireless' &&
			type(e.ssid) == 'string' && length(e.ssid) > 0 && type(e.password) == 'string' && type(e.code) == 'string';
	}
	function snapshot() {
		if (type(io.join_snapshot) != 'function') die('runtime_unavailable: Initial handoff snapshot adapter is unavailable');
		let value = io.join_snapshot();
		if (type(value) != 'string' || !length(value) || length(value) > 524288)
			die('identity_error: Initial handoff snapshot is invalid');
		return value;
	}
	function capture_actor(raw, boot, transport) {
		if (transport == null) return null;
		if (type(io.join_capture) != 'function')
			die('runtime_unavailable: Original joining actor capture adapter is unavailable');
		let scope = clone(io.join_capture());
		if (type(scope) != 'object' || scope.error != null || scope.boot !== boot ||
			!match(scope.tag || '', /^[0-9a-f]{64}$/) || type(scope.stamp) != 'string' ||
			!length(scope.stamp) || length(scope.stamp) > 1024)
			die('identity_error: Original joining actor scope is invalid');
		for (let entry in [['identity', 'identity.json'], ['key', 'device.key'], ['join_ca', 'join-ca.crt'],
			['network_ca', 'network-ca.crt'], ['cert', 'device.crt']])
			if (scope[entry[0]] !== raw[entry[1]]) die('identity_error: Original joining actor raw scope changed');
		return { ...scope, state: raw['state.json'], cluster: raw['cluster.json'],
			...(raw.snapshot == null ? {} : {snapshot: raw.snapshot}) };
	}
	function capture(outer_deadline) {
		let raw = raw_files(), data = raw['identity.json'] == null ? null : json(raw['identity.json']), j = data?.joining;
		if (!j || index(['requesting', 'pending'], j.status) < 0) return null;
		let key = raw['device.key'], hash = type(key) == 'string' ? crypto.key_fingerprint(key) : null;
		if (data.schema !== 1 || data.role != 'unbound' || data.binding ||
			!hash || data.id != substr(hash, 0, 32) || data.fingerprint != hash ||
			!match(j.request_id || '', /^[0-9a-f]{32}$/) || !match(j.secret || '', /^[0-9a-f]{64}$/))
			die('identity_error: Original joining identity is invalid');
		let v = validate_invitation(j.invitation);
		if (v.controller_id == data.id || raw['join-ca.crt'] !== v.ca || j.invitation.ca !== v.ca)
			die('identity_error: Original joining CA no longer matches');
		if (initial_wireless(data)) raw.snapshot = snapshot();
		validate_checkpoint(data, raw);
		if (raw.snapshot != null && j.approval != null && j.approval.handoff == null)
			die('identity_error: Original initial handoff provenance is unavailable');
		let now = io.now(), boot = io.boot(), transport = io.join_transport(v.address);
		if (!clock_value(now) || type(boot) != 'string' || !length(boot) || length(boot) > 128)
			die('clock_error: Joining clock or boot identity unavailable');
		if (outer_deadline != null && !clock_value(outer_deadline))
			die('clock_error: Joining outer deadline is invalid');
		let actor_scope = capture_actor(raw, boot, transport);
		return { raw, data, invitation: v, boot, started: now, actor_scope,
			deadline: outer_deadline == null ? now + ATTEMPT : min(now + ATTEMPT, outer_deadline), transport: clone(transport) };
	}
	function fence(frame) {
		let now = io.now();
		if (!clock_value(now) || io.boot() !== frame.boot || now < frame.started || now >= frame.deadline ||
			!equal({ ...raw_files(), ...(frame.raw.snapshot == null ? {} : {snapshot: snapshot()}) }, frame.raw) ||
			!equal(io.join_transport(frame.invitation.address), frame.transport))
			die('identity_error: Joining request, credentials, transport or deadline changed');
	}
	function write(frame, name, content, object) {
		fence(frame);
		if (frame.deadline - io.now() < 5)
			die('identity_error: Joining deadline cannot cover the existing durable write budget');
		let before = frame.raw[name], error;
		try {
			if (object == null) io.write(name, content);
			else io.save(name, object);
		} catch (e) { error = e.message || 'storage_error: Joining write failed'; }
		let actual = io.read(name);
		if (actual !== content) {
			// Do not repair a replaced object after an uncertain durable write.
			if (actual !== before) die('identity_error: Joining durable object was replaced');
			fence(frame);
			die(error || 'storage_error: Joining write was not durably published');
		}
		frame.raw[name] = content;
		// A write-then-error is acknowledged only from exact actual durable bytes
		// and all original inputs. A scheduler-late effect is never fake success.
		fence(frame);
	}
	function persist(frame, data) { write(frame, 'identity.json', sprintf('%J', data), data); }
	function terminal_error(frame, message) {
		fence(frame);
		let code = match(message || '', /^(invitation_expired|already_registered|not_authorized):/)?.[1];
		if (code) {
			let data = clone(frame.data);
			data.joining.status = 'rejected'; data.joining.error = code;
			persist(frame, data);
		}
		die(message || 'peer_unavailable: Controller enrollment exchange failed');
	}
	function prepare(frame, reply) {
		let j = frame.data.joining;
		if (reply?.request_id != j.request_id) die('protocol_error: Invalid joining response');
		if (reply.status != 'approved') {
			if (index(['pending', 'rejected'], reply.status) < 0) die('protocol_error: Invalid enrollment status');
			return null;
		}
		if (reply.controller_id != frame.invitation.controller_id || reply.network_id != frame.invitation.network_id ||
			!crypto.verify_leaf(frame.invitation.ca, reply.cert, frame.raw['device.key'], frame.data.id))
			die('identity_error: Issued certificate or controller binding is invalid');
		if (j.approval) {
			if (j.approval.cert !== reply.cert) die('identity_error: Original joining approval changed');
			return clone(j.approval);
		}
		let checkpoint = { schema: 1, ...approval_scope(frame.data, frame.raw),
			before_ca: digest(frame.raw['network-ca.crt']), before_cert: digest(frame.raw['device.crt']), cert: reply.cert };
		checkpoint.proof = checkpoint_proof(checkpoint, frame.raw['device.key']);
		if (!checkpoint.proof) die('identity_error: Joining approval proof failed');
		if (frame.raw.snapshot != null) {
			if (type(io.join_handoff) != 'function') die('runtime_unavailable: Initial handoff proof adapter is unavailable');
			let before = {identity:frame.raw['identity.json'],key:frame.raw['device.key'],join_ca:frame.raw['join-ca.crt'],
				network_ca:frame.raw['network-ca.crt'],cert:frame.raw['device.crt']},
				approved = {...before,identity:sprintf('%J',expected_identity(frame.data,frame.invitation)),
					network_ca:frame.invitation.ca,cert:reply.cert};
			let handoff = io.join_handoff(clone(before), clone(approved), frame.raw['state.json'], frame.raw.snapshot, clone(checkpoint));
			checkpoint.handoff = clone(handoff?.ref);checkpoint.proof = checkpoint_proof(checkpoint, frame.raw['device.key']);
			let permitted = approval_prepare({...before,state:frame.raw['state.json'],snapshot:frame.raw.snapshot},checkpoint);
			if (!permitted || permitted.expected_identity !== handoff?.identity)
				die('identity_error: Initial handoff proof does not match original approval');
		}
		return checkpoint;
	}
	function commit(frame, reply, checkpoint) {
		let data = clone(frame.data), j = data.joining, v = frame.invitation;
		if (reply?.request_id != j.request_id) die('protocol_error: Invalid joining response');
		if (reply.status == 'approved') {
			if (!j.approval) {
				j.approval = checkpoint;
				io.locked(() => persist(frame, data));
			}
			for (let entry in [['network-ca.crt', v.ca], ['device.crt', reply.cert]])
				if (frame.raw[entry[0]] !== entry[1]) io.locked(() => write(frame, entry[0], entry[1]));
			data = expected_identity(data, v);
			return io.locked(() => { persist(frame, data); return public_identity(data); });
		}
		return io.locked(() => {
			fence(frame);
			if (index(['pending', 'rejected'], reply.status) < 0) die('protocol_error: Invalid enrollment status');
			if (j.approval) die('identity_error: Original joining approval changed');
			if (j.status != reply.status) { j.status = reply.status; persist(frame, data); }
			return public_identity(data);
		});
	}
	function tick(absolute_deadline) {
		require_adapter();
		let frame = io.locked(() => capture(absolute_deadline));
		if (!frame) return null;
		let j = frame.data.joining, payload = { protocol: 1,
			action: j.status == 'requesting' ? 'join' : 'join_status', id: frame.data.id,
			request_id: j.request_id, secret: j.secret };
		if (j.status == 'requesting') {
			let csr = crypto.csr(frame.raw['device.key'], frame.data.id);
			if (!csr) die('identity_error: Original joining CSR is invalid');
			payload = { ...payload, token: frame.invitation.token,
				network_id: frame.invitation.network_id, name: frame.data.name, csr };
		}
		// This final read fence and the exchange both run outside the lock. Stop
		// can win while I/O is in flight; no local commit then advertises cancel.
		fence(frame);
		let reply, error;
		let timeout_ms = min(16000, int((frame.deadline - io.now()) * 1000));
		if (timeout_ms <= 0) die('identity_error: Joining exchange deadline expired');
		try { reply = io.join_exchange(frame.invitation, payload, frame.transport, timeout_ms); }
		catch (e) { error = e.message || 'peer_unavailable: Controller enrollment exchange failed'; }
		if (error) return io.locked(() => terminal_error(frame, error));
		let checkpoint = prepare(frame, reply);
		if (checkpoint && frame.transport != null) {
			fence(frame);
			if (type(io.join_authorize) != 'function')
				die('runtime_unavailable: Original joining actor permit adapter is unavailable');
			let budget = min(8000, int((frame.deadline - io.now()) * 1000));
			if (budget <= 0) die('identity_error: Joining actor permit deadline expired');
			let proposed = clone(frame.data);proposed.joining.approval = clone(checkpoint);
			if (io.join_authorize(clone(frame.transport), clone(frame.actor_scope), clone(checkpoint),
				sprintf('%J', expected_identity(proposed, frame.invitation)), budget) !== true)
				die('identity_error: Original joining actor permit was not acknowledged');
		}
		return commit(frame, reply, checkpoint);
	}
	return { tick };
}
