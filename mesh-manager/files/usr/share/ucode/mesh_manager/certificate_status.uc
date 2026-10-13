// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as crypto from 'mesh_crypto';

function empty(status, wall) {
	return {observed_at:wall, ca:{status,expires_at:null,remaining_days:null},
		device:{status,expires_at:null,remaining_days:null}};
}

export function certificate_diagnostics(io, wall) {
	let captured;
	try {
		captured = io.locked(() => {
			let identity = io.load('identity.json');
			if (!identity || identity.role == 'unbound') return null;
			return {identity, ca:io.read('network-ca.crt'), device:io.read('device.crt')};
		}, 5);
	} catch (e) { return empty('unavailable', wall); }
	if (!captured) return empty('not_enrolled', wall);
	let identity = captured.identity;
	if (index(['root','ap'], identity.role) < 0) return empty('unavailable', wall);
	let result = crypto.certificate_status(captured.ca, captured.device, identity.id, wall);
	if (identity.role == 'ap' && captured.ca &&
		(!identity.binding?.ca_fingerprint || crypto.fingerprint(captured.ca) != identity.binding.ca_fingerprint)) {
		result.ca.status = 'untrusted';
		result.device.status = 'untrusted';
	}
	return {...result, observed_at:wall};
}
