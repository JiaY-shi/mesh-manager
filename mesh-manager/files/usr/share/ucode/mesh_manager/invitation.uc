// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as crypto from 'mesh_crypto';
import { private_address } from './identity.uc';

// Joining and bootstrap readers share the strict wire validation without
// loading the controller's pairing, member and lifecycle services.
export function joining_code(value) {
	let parts = type(value) == 'string' ? split(value, ':') : [];
	if (length(parts) != 4 || parts[0] != 'MM1' ||
		!private_address(parts[1]) ||
		!match(parts[2], /^[0-9a-f]{64}$/) ||
		!match(parts[3], /^[0-9a-f]{64}$/))
		die('invalid_code: Invalid one-time joining code');
	return { address: parts[1], fingerprint: parts[2], token: parts[3] };
}

export function invitation(value) {
	if (
		type(value) != 'object' ||
		value.protocol != 1 ||
		!private_address(value.address) ||
		!match(value.controller_id || '', /^[0-9a-f]{32}$/) ||
		!match(value.network_id || '', /^[0-9a-f]{32}$/) ||
		!match(value.token || '', /^[0-9a-f]{64}$/) ||
		!match(value.fingerprint || '', /^[0-9a-f]{64}$/) ||
		type(value.ca) != 'string' ||
		length(value.ca) > 4096 ||
		crypto.fingerprint(value.ca) != value.fingerprint ||
		value.port != 37901 ||
		value.enroll_port != 37902 ||
		type(value.name) != 'string' ||
		length(value.name) > 64
	)
		die('invalid_invitation: Invitation identity or address is invalid');
	return {
		protocol: 1,
		address: value.address,
		controller_id: value.controller_id,
		network_id: value.network_id,
		token: value.token,
		fingerprint: value.fingerprint,
		ca: crypto.normalize_cert(value.ca),
		name: value.name,
		port: 37901,
		enroll_port: 37902
	};
}
