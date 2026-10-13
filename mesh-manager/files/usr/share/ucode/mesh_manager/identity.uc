// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as crypto from 'mesh_crypto';
import { valid_text, public_enrollment, equal } from './model.uc';

// Network I/O deliberately runs outside the journal lock. Check the complete
// enrollment again before acknowledging or applying its result under that lock.
export function same_ap_binding(before, after) {
	return before?.role == 'ap' && after?.role == 'ap' && type(before.binding) == 'object' &&
		before.id == after.id && before.fingerprint == after.fingerprint &&
		before.network_id == after.network_id && equal(before.binding, after.binding);
}

export function private_address(value) {
	if (type(value) != 'string' || !match(value, /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/)) return false;
	let p = map(split(value, '.'), (item) => int(item));
	return (
		!length(filter(p, (n) => n < 0 || n > 255)) &&
		(p[0] == 10 ||
			(p[0] == 172 && p[1] >= 16 && p[1] <= 31) ||
			(p[0] == 192 && p[1] == 168) ||
			(p[0] == 169 && p[1] == 254))
	);
}
export function public_identity(data, enrollment) {
	if (!data) return { role: 'unbound' };
	return {
		id: data.id,
		fingerprint: data.fingerprint,
		role: data.role,
		gateway: data.role == 'root' ? data.gateway || 'router' : null,
		cluster_version: data.role == 'ap' ? data.cluster_version || 0 : null,
		name: data.name || null,
		network_id: data.network_id || data.binding?.network_id || null,
		controller_id: data.role == 'root' ? data.id : data.binding?.controller_id || null,
		address: data.address || data.binding?.address || null,
		joining: data.joining
			? { request_id: data.joining.request_id, status: data.joining.status }
			: null,
		overrides: data.overrides || null,
		enrollment: enrollment == null ? public_enrollment(data.enrollment) : enrollment
	};
}

export function identity_service(io) {
	function identity() {
		let key = io.read('device.key'),
			data = io.load('identity.json');
		if (!key) {
			if (data) die('identity_error: Device private key is missing');
			key = crypto.keypair();
			if (!key) die('identity_error: Ed25519 key generation failed');
			io.write('device.key', key);
		}
		let hash = crypto.key_fingerprint(key);
		if (!hash) die('identity_error: Invalid device private key');
		if (!data) {
			data = {
				schema: 1,
				id: substr(hash, 0, 32),
				fingerprint: hash,
				role: 'unbound',
				binding: null,
				joining: null,
				overrides: null
			};
			io.save('identity.json', data);
		}
		if (
			data.schema != 1 ||
			data.id != substr(hash, 0, 32) ||
			data.fingerprint != hash ||
			index(['unbound', 'root', 'ap'], data.role) < 0
		)
			die('identity_error: Device identity does not match private key');
		return data;
	}
	function root(name, address) {
		let data = identity();
		if (data.role == 'ap' || data.binding)
			die('already_bound: This device belongs to another controller');
		if (!valid_text(name, 1, 64)) die('invalid_name: Invalid network name');
		if (!private_address(address))
			die('invalid_address: Use an explicit private management address');
		if (time() < 1704067200)
			die('clock_error: Set a valid device clock before issuing certificates');
		let key = io.read('network-ca.key');
		if (!key) {
			key = crypto.keypair();
			if (!key) die('identity_error: CA key generation failed');
			io.write('network-ca.key', key);
		}
		let ca = io.read('network-ca.crt');
		if (!ca) {
			ca = crypto.ca(key, data.id);
			if (!ca) die('identity_error: CA certificate generation failed');
			io.write('network-ca.crt', ca);
		}
		let cert = io.read('device.crt');
		if (!cert || !crypto.verify_leaf(ca, cert, io.read('device.key'), data.id)) {
			cert = crypto.sign(key, ca, crypto.csr(io.read('device.key'), data.id), data.id);
			if (!cert) die('identity_error: Controller certificate generation failed');
			io.write('device.crt', cert);
		}
		data.role = 'root';
		if (!data.network_id) data.network_id = io.random(16);
		data.name = name;
		data.address = address;
		io.save('identity.json', data);
		return public_identity(data);
	}
	return {
		identity,
		root,
		csr: () => {
			let data = identity();
			return crypto.csr(io.read('device.key'), data.id);
		}
	};
}
