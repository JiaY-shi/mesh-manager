// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { start } from 'mesh_process';

export function job_scheduler(loop, callback) {
	let timer;
	return ms => {
		if (ms) { if (timer) timer.set(ms); else timer = loop.timer(ms,callback); }
		// cancel() destroys the ucode callback; the next submission must create
		// a new resource. A negative set() fires immediately on some libubox versions.
		else if (timer) { timer.cancel(); timer = null; }
	};
}

function failure(code) {
	return { ok: false, error: { code, message: 'Mesh Manager preview could not complete' } };
}
export function preview_work(handler, pause) {
	let result;
	for (let attempt = 0; attempt < 3; attempt++) {
		result = handler();
		if (result?.ok !== false || result.error?.code != 'busy' || attempt == 2)
			return { ...result, retries: attempt };
		// Only the fixed read-only preview worker calls this. Native supervision
		// retains one 30s deadline across all attempts; writes never retry here.
		(pause || sleep)(250 * (attempt + 1));
	}
}
export function preview_result(result) {
	if (result?.code != 0) return failure(result?.code == -2 ? 'request_timeout' : 'backend_unavailable');
	try {
		let reply = json(result.stdout);
		if (type(reply) == 'object' && type(reply.ok) == 'bool' &&
			(reply.ok ? type(reply.data) == 'object' : type(reply.error?.code) == 'string' &&
				type(reply.error?.message) == 'string')) return reply;
	} catch (e) {}
	return failure('backend_unavailable');
}
export function deferred_preview(request, spawn) {
	// rpcd has already authenticated the existing write ACL. Never forward session tokens.
	let deferred = request.defer(), replied = false;
	let job = (spawn || start)(['/usr/bin/ucode', '/usr/libexec/mesh-manager-rpc-worker', 'repair_preview'],
		'', 30000, result => {
			if (replied) return;
			replied = true;
			// A shorter administrator-set rpcd timeout may have already invalidated this request.
			try { request.reply(preview_result(result)); } catch (e) {}
		});
	return job ? deferred : failure('busy');
}

export function deferred_settings(method, request, spawn) {
	let args = { ...request.args }; delete args.ubus_rpc_session;
	let input = sprintf('%J', args);
	if (length(input) > 131072) return failure('invalid_request');
	let deferred = request.defer();
	let job = (spawn || start)(['/usr/bin/ucode', '/usr/libexec/mesh-manager-rpc-worker', method], input, 30000, result => {
		try { request.reply(preview_result(result)); } catch (ignored) {}
	});
	return job ? deferred : failure('busy');
}
