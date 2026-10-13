// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { dispatch } from 'mesh_manager.runtime';
import { advanced_dispatch, cluster_status, status_detail } from 'mesh_manager.advanced';
import { boot, now, random } from 'mesh_manager.durable';
import { sha256 } from 'mesh_crypto';
import { redacted_diagnostics } from 'mesh_manager.diagnostics';
import * as durable from 'mesh_manager.durable';
import { certificate_diagnostics } from 'mesh_manager.certificate_status';
import { current_attention } from 'mesh_manager.attention';
import { wake_service } from 'mesh_manager.service_runtime';
import { onboard_standby_stop } from 'mesh_manager.onboarding';

export function invoke(method, args) {
	try {
		let result;
		if (args?.takeover===true && index(['stage','mesh_stage','repair_stage','local_overrides_stage'],method)>=0)
			wake_service();
		if(method=='apply') {
			let state=durable.load('state.json');
			if(state?.active?.id==args?.transaction_id && state.active.mesh_enabled===true)onboard_standby_stop();
		}
		if (method == 'roaming_status') {
			result = dispatch('status', { view:'wireless' }).local.roaming;
			let boot_id=boot();
			result={...result,boot_id,revision:sha256(boot_id+sprintf('%J',result)),observed_uptime_ms:int(now()*1000),stale:false};
		} else if (index(['status', 'diagnostics'], method) >= 0) {
			let view = method == 'diagnostics' ? 'diagnostics' : args?.view || 'overview';
			result = dispatch(method, { view });
			result.cluster = cluster_status(view);
			if (index(['overview','diagnostics'],view)>=0) {
				result.attention=current_attention(result,boot(),now(),time());
				for(let member in result.cluster.members)delete member.attention;
			}
			if(view=='overview') {
				let members=filter(result.cluster.members || [],m=>m.authorized===true);
				result.cluster.member_counts={total:length(members),online:length(filter(members,m=>m.online===true))};
				delete result.cluster.members;
			}
			if (view == 'diagnostics') result.local.certificates = certificate_diagnostics(durable, time());
			if (args?.history_mode) {
				if (view != 'history' || args.history_mode != 'paged') die('invalid_request: Invalid history status mode');
				result.history_counts = { local: length(result.history || []), cluster: length(result.cluster.history || []),
					repair: length(result.cluster.repair_history || []), lifecycle: length(result.cluster.lifecycle_history || []),
					metadata:length(result.cluster.metadata_history || []) };
				delete result.history;
				delete result.cluster.history;
				delete result.cluster.repair_history;
				delete result.cluster.lifecycle_history;
				delete result.cluster.metadata_history;
			}
			if (method == 'diagnostics') {
				result=redacted_diagnostics(result,random(32),time());
			}
		} else if (method == 'status_detail') result = status_detail(args || {});
		else if (method == 'confirm') {
			let active = dispatch('status', { view: 'nodes' }).active;
			result = active?.kind == 'overrides' ? advanced_dispatch('local_overrides_confirm', args || {}) :
				active?.kind == 'repair' ? advanced_dispatch('repair_confirm', args || {}) :
				active?.mesh_enabled != null ? advanced_dispatch('mesh_confirm', args || {}) : dispatch(method, args || {});
		}
		else if (method == 'release')
			die('preview_required: Use the guarded Mesh disable preview');
		else if (index(['preview', 'stage', 'apply', 'confirm', 'rollback'], method) >= 0)
			result = dispatch(method, args || {});
		else result = advanced_dispatch(method, args || {});
		if (index(['enrollment_start','controller_init','setup_create'],method)>=0) wake_service();
		return { ok: true, data: result };
	} catch (e) {
		let text = '' + e,
			found = match(text, /([a-z_]+): ([^\n]+)/);
		return {
			ok: false,
			error: {
				code: found?.[1] || 'internal_error',
				message: found?.[2] || 'Mesh Manager request failed'
			}
		};
	}
}
