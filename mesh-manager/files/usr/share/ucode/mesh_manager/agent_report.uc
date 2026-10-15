// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as client_events from './client_events.uc';
import { public_op } from './model.uc';
import { recovery_report } from './controller_loss.uc';
import { software_status } from './software_status.uc';
import {sanitize_migration_receipt} from './migration_model.uc';

export function sanitize_report(r) {
	let clients = client_events.sanitize_clients(r.clients);
	let command = r.command
		? {
				id: r.command.id,
				status: r.command.status,
				error: r.command.error || null,
				transaction: r.command.transaction,
				transaction_id: r.command.transaction_id || null,
			version: r.command.version,
				mesh: r.command.mesh === true,
				health_confirmed:r.command.health_confirmed === true,
				repair: r.command.repair === true,
				conflicts: r.command.conflicts || [],
				plan: r.command.plan
					? { ...r.command.plan, ops: map(r.command.plan.ops || [], public_op) }
					: null
			}
		: null;
	return {
		version: type(r.version) == 'int' ? r.version : null,
		local_version: type(r.local_version) == 'int' ? r.local_version : null,
		mesh_enabled: type(r.mesh_enabled) == 'bool' ? r.mesh_enabled : null,
		configured: r.configured === true,
		data_gateway:r.data_gateway===true,
		model: r.model || null,
		software: software_status(r.software),
		management: r.management || null,
		drift: type(r.drift) == 'array' ? r.drift : null,
		health: r.health || null,
		backhaul: type(r.backhaul)=='object' ? r.backhaul : null,
		transaction: r.transaction || null,
		controller_recovery: recovery_report(r.controller_recovery),
		clients,
		clients_complete: r.clients_complete === true && type(r.clients) == 'array' &&
			length(clients) == length(r.clients),
		migration:sanitize_migration_receipt(r.migration),
		command
	};
}
