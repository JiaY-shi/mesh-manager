// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as crypto from 'mesh_crypto';
import { equal, valid_text } from './model.uc';
import { recent_presence } from './attention.uc';
import { lifecycle_busy, configuration_busy } from './lifecycle.uc';

// This is a receipt for an actually reported first commit. It issues no new
// configuration and never reconstructs catchup from an invented old report.
// The caller authenticates the certificate and isolated ingress, and seals the
// returned object with the existing nonce-bound controller response protocol.
export function handoff_receipt(root, state, id, request, io) {
	const fields = ['protocol', 'network_id', 'action', 'nonce', 'request_id', 'version', 'transaction_id'];
	if (type(request) != 'object' || !equal(sort(keys(request)), sort(fields)) ||
		request.protocol !== 1 || request.action != 'handoff_check' ||
		request.network_id != root?.network_id ||
		!match(request.nonce || '', /^[0-9a-f]{32}$/) ||
		!match(request.request_id || '', /^[0-9a-f]{32}$/) ||
		type(request.version) != 'int' || request.version < 1 || request.version > 2147483647 ||
		!valid_text(request.transaction_id, 1, 96, true))
		die('invalid_request: Invalid first configuration receipt request');
	let member = state?.members?.[id], joined = state?.requests?.[request.request_id],
		report = member?.report, transaction = report?.transaction, command = report?.command,
		root_id = 'catchup-' + sprintf('%016d', request.version);
	if (root?.role != 'root' || member?.authorized !== true || member.id !== id ||
		member.control_bound !== true || member.control_protocol !== 1 || member.mesh_paused === true ||
		joined?.id !== id || joined.status != 'approved' ||
		type(joined.cert) != 'string' || !length(joined.cert) || length(joined.cert) > 16384 ||
		!match(member.certificate || '', /^[0-9a-f]{64}$/) ||
		crypto.fingerprint(joined.cert) !== member.certificate ||
		type(state.version) != 'int' || state.version < request.version || state.version > 2147483647 ||
		member.version !== request.version || !state.intent)
		die('handoff_conflict: Original approved membership or Root version changed');
	// A newer Root intent must not strand an already committed first AP. This
	// receipt still confirms only the exact original reported version below;
	// after retiring bootstrap, the ordinary agent can catch up to the new one.
	if (!recent_presence(io.presence?.(id), io.boot(), io.now()))
		die('node_offline: A fresh authenticated first configuration report is required');
	if (report?.configured !== true || report.mesh_enabled !== true || report.local_version !== 1 ||
		report.version !== request.version || type(report.drift) != 'array' || length(report.drift) ||
		transaction?.kind != 'configure' || transaction.status != 'committed' ||
		transaction.mesh_enabled != null || transaction.id !== request.transaction_id ||
		command?.id !== root_id || command.status != 'committed' ||
		command.transaction !== root_id || command.transaction_id !== transaction.id ||
		command.version !== request.version || command.mesh === true || command.repair === true ||
		command.error != null || type(command.conflicts) != 'array' || length(command.conflicts))
		die('handoff_unhealthy: A matching real first commit without configuration drift is required');
	let local = io.local?.handoff_status?.();
	if (type(local) != 'object' || type(local.paused) != 'bool' || local.configured !== true)
		die('handoff_conflict: Controller configuration state is unavailable');
	if (lifecycle_busy(state) || configuration_busy(state, { ...io, local: { repair_status: () => local } }) || local.paused === true)
		die('busy: Complete Root configuration and recovery before accepting first configuration');
	return { controller_id: root.id, network_id: root.network_id,
		receipt: { schema: 1, status: 'committed', request_id: request.request_id, node_id: id,
			root_id, root_version: request.version, transaction_id: transaction.id,
			local_version: 1, certificate: member.certificate } };
}
