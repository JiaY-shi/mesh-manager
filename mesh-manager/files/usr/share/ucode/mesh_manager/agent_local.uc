// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as durable from './durable.uc';
import { dispatch as local_dispatch, agent_status, restoration_committed, authorize_restoration } from './runtime.uc';
import { handoff_stage } from './handoff_runtime.uc';
import { onboard_standby_stop } from './onboarding.uc';

// Local transaction adapters shared by AP polling and explicit Root/RPC work.
// Importing these adapters must not load controller orchestration.
export function agent_local() {
	let local = {
		preview: (intent) => local_dispatch('preview', { intent }),
		local_overrides_preview: (intent, context) => local_dispatch('local_overrides_preview', { intent, context }),
		local_overrides_stage: (intent, request_id, takeover, approval, context) =>
			local_dispatch('local_overrides_stage', { intent, request_id, takeover, approval, context }),
		mesh_preview: (enabled, intent) => local_dispatch('mesh_preview', { enabled, intent }),
		mesh_stage: (enabled, intent, request_id, takeover, approval) =>
			local_dispatch('mesh_stage', { enabled, intent, request_id, takeover, approval }),
		authorize_restoration,
		repair_preview: (intent) => local_dispatch('repair_preview', { intent }),
		repair_stage: (intent, request_id, takeover, approval) =>
			local_dispatch('repair_stage', { intent, request_id, takeover, approval }),
		stage: (intent, request_id, takeover, approval) =>
			local_dispatch('stage', { intent, request_id, takeover, approval }),
		first_handoff_stage: handoff_stage,
		apply: (transaction_id) => {
			let state=durable.load('state.json');
			if(state?.active?.id==transaction_id && state.active.mesh_enabled===true)onboard_standby_stop();
			return local_dispatch('apply', { transaction_id });
		},
		confirm: (transaction_id) => local_dispatch('confirm', { transaction_id }),
		rollback: (transaction_id) => local_dispatch('rollback', { transaction_id }),
		status: (view) => local_dispatch('status', { view: view || 'nodes' }),
		agent_status,
		restoration_committed
	};
	local.repair_status = () => {
		let state = durable.load('state.json'), active = state?.active;
		return active ? { id: active.id, kind: active.kind, status: active.status,
			mesh_enabled: active.mesh_enabled ?? null, paused: state.paused === true } :
			state?.paused === true ? { paused: true, status: 'committed' } : null;
	};
	local.handoff_status = () => {
		let state = durable.load('state.json'), active = state?.active;
		return state?.schema === 1 ? { paused: state.paused, configured: state.intent != null,
			status: active?.status || 'committed' } : null;
	};
	return local;
}
