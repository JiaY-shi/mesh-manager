// SPDX-License-Identifier: GPL-2.0-only
'use strict';
'require baseclass';
'require rpc';
'require request';

var sequence = 0;
function invoke(method, args, object, timeout) {
	return new Promise(function(resolve, reject) {
		var call = { object: object || 'mesh-manager.sync', method: method, raise: true, resolve: resolve, reject: reject };
		var frame = { jsonrpc: '2.0', id: 'mesh-job-' + (++sequence), method: 'call',
			params: [rpc.getSessionID(), call.object, call.method, args] };
		var reply = rpc.parseCallReply.bind(rpc, call);
		request.post(rpc.getBaseURL(), frame, { timeout: timeout || 5000, nobatch: true, credentials: true }).then(reply, reply);
	});
}
function failure(code) { return { ok:false, error:{code:code,message:code} }; }
return baseclass.extend({
	action: function(method, args) {
		if (['local_overrides_stage','local_overrides_confirm','mesh_preview','mesh_stage','mesh_confirm','migration_preflight','migration_apply'].indexOf(method)<0)
			return Promise.reject(new Error('Invalid local settings operation'));
		// The supervised backend has a 30s deadline. LuCI's default 20s
		// transport timeout must not abandon a write that is still executing.
		// Never replay a timeout: status retains the durable transaction result.
		return invoke(method,args,'mesh-manager',35000).catch(function(error) {
			error.code=method==='mesh_preview' ? 'request_timeout' : 'outcome_unknown';
			throw error;
		});
	},
	preview: function(control, method, args, object) {
		control = control || {};
		var bytes = new Uint8Array(16), job, cancelled = false, cancelRequest;
		window.crypto.getRandomValues(bytes);
		var id = Array.from(bytes).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
		var deadline = window.performance.now() + 35000;
		control.cancel = function() {
			cancelled = true;
			if (job && !cancelRequest) cancelRequest = invoke('job_cancel', { job_id:job.job_id },object);
			return cancelRequest || Promise.resolve();
		};
		function follow(reply) {
			if (cancelled) return control.cancel().then(function() { return failure('job_cancelled'); });
			if (!reply || reply.ok !== true) return reply;
			job = reply.data;
			if (!job || typeof job.job_id !== 'string') return failure('backend_unavailable');
			if (['complete','failed','cancelled'].indexOf(job.status) >= 0)
				return job.result || failure('backend_unavailable');
			if (window.performance.now() >= deadline) {
				return control.cancel().then(function() { return failure('request_timeout'); });
			}
			if (control.progress) control.progress(job.status);
			return new Promise(function(resolve) { window.setTimeout(resolve, 750); }).then(function() {
				return cancelled ? follow({ok:true,data:job}) : invoke('job_get', {job_id:job.job_id},object).then(follow);
			});
		}
		return invoke(method || 'repair_preview', Object.assign({}, args || {}, {request_id:id}),object).then(function(reply) {
			// Preserve the ID even when cancel was clicked while admission was in flight.
			if (reply && reply.ok) job = reply.data;
			return follow(reply);
		}).finally(function() { delete control.cancel; });
	}
});
