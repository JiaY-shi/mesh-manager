// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { invoke } from 'mesh_manager.rpc_dispatch';
import { deferred_preview, deferred_settings } from 'mesh_manager.rpc_async';
import { job_call } from 'mesh_manager.rpc_job_service';
import { history_call, history_clear_call } from 'mesh_manager.history_service';
import { client_call } from 'mesh_manager.client_service';
import { log_call } from 'mesh_manager.diagnostic_service';
import { topology_call } from 'mesh_manager.topology_service';
function call(method, request) { return invoke(method, request?.args || {}); }
let methods = {};
function handler(method) {
	return (request) => call(method, request);
}
methods.status = { args: { view: '', history_mode: '' }, call: handler('status') };
methods.status_detail = { args: { kind: '', node_id: '', id: '' }, call: handler('status_detail') };
methods.diagnostics = { call: handler('diagnostics') };
// iwinfo is served by this rpcd process. Release the request before a worker
// queries it; a synchronous handler would block its own scan/info replies.
methods.discover = { args: { mode: '', timeout: 0 }, call: request => deferred_settings('discover', request) };
methods.onboard_status = { call: handler('onboard_status') };
methods.onboard_stop = { call: handler('onboard_stop') };
methods.preview = { args: { intent: {} }, call: request => deferred_settings('preview', request) };
methods.stage = {
	args: { intent: {}, request_id: '', takeover: false, approval: {} },
	call: request => deferred_settings('stage', request)
};
for (let method in ['apply', 'confirm', 'rollback'])
	methods[method] = { args: { transaction_id: '' }, call: handler(method) };
methods.release = {
	args: { request_id: '', takeover: false },
	call: (request) => call('release', request)
};
methods.controller_init = {
	args: { name: '', address: '', gateway: '', local: {}, takeover: false },
	call: handler('controller_init')
};
methods.node_revoke = { args: { node_id: '' }, call: handler('node_revoke') };
methods.node_rename_preview = { args: { node_id: '', name: '' }, call: handler('node_rename_preview') };
methods.node_rename = { args: { request_id: '', approval: {}, takeover: false }, call: handler('node_rename') };
methods.cluster_preflight = {
	args: { intent: {}, request_id: '', maintenance: false },
	call: request => deferred_settings('cluster_preflight', request)
};
methods.cluster_apply = {
	args: { transaction_id: '', approval: {}, takeover: false },
	call: request => deferred_settings('cluster_apply', request)
};
methods.cluster_rollback = { args: { transaction_id: '' }, call: handler('cluster_rollback') };
methods.local_overrides = {
	args: { local: {}, takeover: false },
	call: handler('local_overrides')
};
methods.repair_preview = { call: deferred_preview };
methods.local_overrides_preview = { args: { local: {} }, call: request => deferred_settings('local_overrides_preview', request) };
methods.local_overrides_stage = { args: { local: {}, request_id: '', takeover: false, approval: {} },
	call: request => deferred_settings('local_overrides_stage', request) };
methods.local_overrides_confirm = { args: { transaction_id: '' }, call: request => deferred_settings('local_overrides_confirm', request) };
methods.repair_stage = { args: { request_id: '', takeover: false, approval: {} },
	call: request => deferred_settings('repair_stage', request) };
methods.repair_confirm = { args: { transaction_id: '' }, call: handler('repair_confirm') };
methods.node_repair = { args: { node_id: '', request_id: '' }, call: handler('node_repair') };
methods.node_repair_apply = {
	args: { node_id: '', request_id: '', approval: {}, takeover: false }, call: handler('node_repair_apply')
};
methods.node_repair_rollback = { args: { node_id: '', request_id: '' }, call: handler('node_repair_rollback') };
methods.setup_create = {
	args: { name: '', address: '', gateway: '', local: {}, intent: {}, request_id: '', takeover: false },
	call: request => deferred_settings('setup_create', request)
};
methods.mesh_preview = { args: { enabled: false }, call: request => deferred_settings('mesh_preview', request) };
methods.mesh_stage = {
	args: { enabled: false, request_id: '', approval: {}, takeover: false }, call: request => deferred_settings('mesh_stage', request)
};
methods.mesh_confirm = { args: { transaction_id: '' }, call: request => deferred_settings('mesh_confirm', request) };
methods.mesh_stop_prepare = { args: { request_id: '' }, call: handler('mesh_stop_prepare') };
methods.node_mesh_prepare = { args: { node_id: '', enabled: false, request_id: '' }, call: handler('node_mesh_prepare') };
methods.mesh_stop_apply = { args: { request_id: '', approval: {}, takeover: false }, call: handler('mesh_stop_apply') };
methods.mesh_stop_cancel = { args: { request_id: '' }, call: handler('mesh_stop_cancel') };
methods.enrollment_start = {
	args: { name: '', local: {}, ssid: '', password: '', bssid: '', device: '', candidate: {}, takeover: false }, call: handler('enrollment_start')
};
methods.enrollment_stop = { call: handler('enrollment_stop') };
return { 'mesh-manager': methods, 'mesh-manager.topology': {
	nodes:{args:{cursor:'',limit:0,fields:[],if_revision:''},call:request=>topology_call('nodes',request)},
	links:{args:{cursor:'',limit:0,fields:[],if_revision:''},call:request=>topology_call('links',request)},
	detail:{args:{node_id:'',fields:[],if_revision:''},call:request=>topology_call('detail',request)}
}, 'mesh-manager.diag': {
	export:{call:handler('diagnostics')},
	packages:{args:{request_id:''},call:request=>job_call('diagnostic_packages',request)},
	run:{args:{check:'',node_id:'',request_id:''},call:request=>job_call('diagnostic_run',request)},
	job_get:{args:{job_id:''},call:request=>job_call('job_get',request)},
	job_cancel:{args:{job_id:''},call:request=>job_call('job_cancel',request)},
	logs:{args:{cursor:'',limit:0,fields:[],if_revision:''},call:request=>log_call('logs',request)},
	clear_logs:{args:{expected_revision:'',request_id:''},call:request=>log_call('clear_logs',request)} },
	'mesh-manager.roaming': { status:{call:handler('roaming_status')},
		clients:{args:{node_id:'',cursor:'',limit:0,fields:[],if_revision:''},call:request=>client_call('clients',request)},
		history:{args:{node_id:'',cursor:'',limit:0,fields:[],if_revision:''},call:request=>client_call('history',request)} }, 'mesh-manager.sync': {
	clear_history: { args: { group:'', expected_revision:'', request_id:'' }, call:history_clear_call },
	history: { args: { group: '', cursor: '', limit: 0, fields: [], if_revision: '' }, call: history_call },
	repair_preview:{args:{request_id:''},call:request=>job_call('repair_preview',request)},
	local_overrides_preview:{args:{request_id:'',local:{}},call:request=>job_call('local_overrides_preview',request)},
	job_get:{args:{job_id:''},call:request=>job_call('job_get',request)},
	job_cancel:{args:{job_id:''},call:request=>job_call('job_cancel',request)}
} };
