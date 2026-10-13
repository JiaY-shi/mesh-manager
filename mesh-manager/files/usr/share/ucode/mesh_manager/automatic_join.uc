// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { private_address } from './identity.uc';
import { invitation } from './invitation.uc';

// First enrollment trusts the LAN or selected password-protected Wi-Fi.
// Public discovery contains no device secret. Pin its CA before requesting
// a short-lived, CSR-bound machine credential over authenticated TLS.
export function automatic_controller(value, address, fingerprint, verify) {
	if (value?.protocol !== 1 || value.address !== address || !private_address(address) ||
		!match(value.controller_id || '', /^[0-9a-f]{32}$/) ||
		!match(value.network_id || '', /^[0-9a-f]{32}$/) ||
		value.port !== 37901 || value.enroll_port !== 37902 ||
		!match(value.fingerprint || '', /^[0-9a-f]{64}$/) ||
		verify(value.ca || '') !== value.fingerprint || fingerprint && fingerprint !== value.fingerprint)
		die('identity_error: Invalid discovered Mesh controller');
	return value;
}
export function automatic_ticket(info, identity, io) {
	let ticket = invitation(io.request(info, { protocol: 1, action: 'auto_invite',
		id: identity.id, request_id: io.random(16), secret: io.random(32), csr: io.csr(identity.id) }));
	if (ticket.address !== info.address || ticket.controller_id !== info.controller_id ||
		ticket.network_id !== info.network_id || ticket.fingerprint !== info.fingerprint || ticket.ca !== info.ca)
		die('identity_error: Automatic enrollment changed controller identity');
	return { ...ticket, code: 'MM1:' + ticket.address + ':' + ticket.fingerprint + ':' + ticket.token };
}

// Public inspection supplies no enrollment secret. A fresh challenge proves
// possession of the selected controller key before an unbound AP sets time.
export function enrollment_clock_witness(controller, nonce, io) {
	if (!match(nonce || '', /^[0-9a-f]{32}$/))
		die('invalid_request: Invalid enrollment clock challenge');
	let wall = io.time();
	if (type(wall) != 'int' || wall < 1704067200 || wall > 4102444800)
		die('clock_error: Controller clock is unavailable');
	let payload = sprintf('%J', { protocol: 1, kind: 'enrollment_clock', nonce,
		controller_id: controller.id, network_id: controller.network_id,
		address: controller.address, fingerprint: io.fingerprint(io.read('network-ca.crt')), wall }),
		certificate = io.read('device.crt'), signature = io.sign(io.read('device.key'), payload);
	if (type(certificate) != 'string' || length(certificate) > 4096 ||
		!match(signature || '', /^[0-9a-f]{128}$/))
		die('identity_error: Controller clock signature is unavailable');
	return { payload, certificate, signature };
}

export function synchronize_enrollment_clock(info, nonce, elapsed, io) {
	if (!match(nonce || '', /^[0-9a-f]{32}$/) || type(elapsed) != 'int' || elapsed < 0 || elapsed > 9000)
		die('clock_error: Enrollment clock challenge expired');
	let proof = info.clock_proof;
	if (proof == null) {
		// Old controllers remain compatible when their CA is already valid at
		// local time. A missing proof can never authorize a clock change.
		if (io.ca_status(info.ca, io.time()) != 'valid')
			die('clock_error: Synchronize device time or update the controller');
		return false;
	}
	if (type(proof.payload) != 'string' || length(proof.payload) > 2048 ||
		type(proof.certificate) != 'string' || length(proof.certificate) > 4096 ||
		!match(proof.signature || '', /^[0-9a-f]{128}$/))
		die('identity_error: Invalid controller clock proof');
	let value; try { value = json(proof.payload); } catch (e) { die('identity_error: Invalid controller clock payload'); }
	if (type(value) != 'object' || length(keys(value)) != 8 || value.protocol !== 1 ||
		value.kind !== 'enrollment_clock' || value.nonce !== nonce ||
		value.controller_id !== info.controller_id || value.network_id !== info.network_id ||
		value.address !== info.address || value.fingerprint !== info.fingerprint ||
		type(value.wall) != 'int' || value.wall < 1704067200 || value.wall > 4102444800 ||
		io.verify_at(info.ca, proof.certificate, info.controller_id, proof.payload, proof.signature, value.wall) !== true)
		die('identity_error: Controller clock authentication failed');
	let target = value.wall + int(elapsed / 2000);
	if (io.time() >= target - 5 && io.time() <= target + 5) return false;
	if (io.adjust(target) !== true || io.time() < target - 5 || io.time() > target + 5)
		die('clock_error: Authenticated controller time could not be applied');
	return true;
}
