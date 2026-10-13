// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal } from './model.uc';
import { local_intent } from './extended.uc';
import { settings_context } from './local_settings.uc';
import { cluster_busy, repair_pending } from './repair.uc';
export function root_settings(io, pairing, method, args) {
	let data = pairing.root(), state = pairing.state(), local = io.load('state.json');
	if (method == 'local_overrides_confirm') {
		if (local?.active?.kind != 'overrides' || local.active.id != args.transaction_id)
			die('invalid_state: Local settings confirmation does not match the transaction');
		if (local.active.status != 'committed' && !equal(local.active.settings_context,
			{ ...settings_context(data, local, local.active.settings_context.record.values), root_version: state.version }))
			die('preview_changed: Local settings identity or controller intent changed before confirmation');
		return io.local.confirm(args.transaction_id);
	}
	if (!local?.intent || local.paused === true) die('mesh_disabled: Enable Mesh before editing local settings');
	if (cluster_busy(state) || repair_pending(state)) die('busy: A cluster operation is pending');
	if (!state.intent) die('not_managed: Controller has no confirmed network intent');
	let context = settings_context(data, local, args.local),
		intent = local_intent(state.intent, args.local, true, data.gateway, data.id);
	context.root_version = state.version;
	if (method == 'local_overrides_preview') return { ...io.local.local_overrides_preview(intent, context), root_version: state.version };
	if (args.approval?.root_version != state.version) die('preview_changed: Controller intent version changed');
	let approval = clone(args.approval); delete approval.root_version;
	return io.local.local_overrides_stage(intent, args.request_id, args.takeover, approval, context);
}
