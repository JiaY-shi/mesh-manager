// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { canonical } from './model.uc';
import { preview_result } from './rpc_async.uc';

export function job_token(value) {
	if (type(value) != 'string' || length(value) != 32) return false;
	for (let i = 0; i < 32; i++) if (index('0123456789abcdef', substr(value, i, 1)) < 0) return false;
	return true;
}

// Admission is limited to previews and fixed, bounded diagnostics. Configuration writes
// retain their persistent transaction state machine and are never replayed here.
export function job_arguments(method, args) {
	if (type(args) != 'object') return false;
	if (method == 'repair_preview') return !length(keys(args));
	if (method == 'diagnostic_packages') return !length(keys(args));
	if (method == 'diagnostic_run') return length(keys(args))==2 && index(['node_ping','node_trace','local_dns','local_address_conflict','local_radios','local_regulatory','local_upstream_dns'],args.check)>=0 && job_token(args.node_id);
	return method == 'local_overrides_preview' && length(keys(args)) == 1 &&
		type(args.local) == 'object' && length(sprintf('%J', args.local)) <= 8192;
}

function error(code) {
	return { ok:false, error:{code, message:'Mesh Manager job could not complete',
		retryable:index(['busy','job_expired'],code) >= 0} };
}

// io owns the clock, ACL checks and native worker. This bounded in-memory queue
// contains no durable changes and is discarded on rpcd restart, with explicit
// job_expired for old IDs. Session credentials never leave this process.
export function job_queue(io) {
	let jobs = [], running = 0, pumping = false, next_probe = 0;
	const capacity = 8, result_limit = 131072, lifetime = 120000;
	function public_job(j) {
		return {ok:true,data:{job_id:j.id,status:j.status,deadline:j.deadline,
			observed_uptime_ms:io.now(),boot_id:io.boot,revision:j.revision,stale:false,
			...(j.finished != null ? {result:j.result,finished_uptime_ms:j.finished} : {})}};
	}
	function done(j, result, status) {
		j.status = status || (result?.ok === true ? 'complete' : 'failed');
		j.result = result; j.finished = io.now();
		j.revision++;
		delete j.args;
	}
	function authorized(sid, method, action, callback) {
		let result;
		function respond(value) { if(callback)callback(value);else result=value; }
		if (!job_token(sid)) respond(error('not_authorized'));
		else io.authorize(sid,method,allowed=>{
			let value;
			try { value=allowed===true ? action() : error('not_authorized'); }
			catch(e) { value=error('backend_unavailable'); }
			respond(value);
		});
		return result;
	}
	function prune() {
		let now = io.now();
		jobs = filter(jobs, j => j.finished == null || now - j.finished < lifetime);
	}
	let pump;
	// ucode loop bindings are shared by closures: capture each job in its own
	// invocation before registering either ACL or worker callbacks.
	function check_job(j) {
		j.checking = true;
		io.authorize(j.sid,j.method,allowed=>{
			delete j.checking;
			if (j.finished != null) return;
			if (allowed !== true || io.now() >= j.deadline) {
				done(j,error(allowed===true?'request_timeout':'not_authorized'));
				j.worker?.cancel();return;
			}
			if (j.status != 'queued' || running >= io.workers) return;
			try {
				let worker = io.spawn(j.method, j.args, int(min(j.deadline-io.now(),30000)), result => {
					running--;
					delete j.worker;
					if (j.finished == null) {
						let reply = length(result?.stdout || '') <= result_limit ? preview_result(result) : error('result_too_large');
						done(j, io.now() >= j.deadline ? error('request_timeout') : reply);
					}
					pump();
				});
				if (!worker) return;
				j.worker = worker; j.status = 'running'; j.revision++; running++;
			} catch(e) { done(j,error('backend_unavailable')); }
		});
	}
	pump = function() {
		if (pumping) return;
		pumping = true;
		try {
			prune();
			for (let j in jobs) {
				if (j.finished != null) continue;
				if (j.deadline <= io.now()) {
					done(j, error('request_timeout'));j.worker?.cancel();continue;
				}
				if (!j.checking) check_job(j);
			}
		} catch (e) {
			for (let j in jobs) if (j.finished == null) {
				done(j,error('backend_unavailable'));j.worker?.cancel();
			}
		}
		pumping = false;
		io.arm(length(filter(jobs,j=>j.finished == null)) ? 1000 :
			length(jobs) ? max(1,int(min(...map(jobs,j=>j.finished+lifetime))-io.now()+1)) : 0);
	};

	function deliver(value, callback) { if(callback)callback(value);return value; }
	function submit(sid, method, args, request_id, callback) {
		if (!job_token(request_id) || !job_arguments(method,args)) return deliver(error('invalid_request'),callback);
		return authorized(sid,method,()=>{
		prune();
		if (method=='diagnostic_run' && index(['local_address_conflict','local_radios','local_regulatory','local_upstream_dns'],args.check)>=0 &&
			(type(io.local_id)!='function' || io.local_id()!=args.node_id)) return error('target_unavailable');
		let digest = io.digest(sprintf('%J',canonical({method,args}))),
			existing = filter(jobs,j=>j.sid == sid && j.request_id == request_id)[0];
		if (existing) return existing.digest == digest ? public_job(existing) : error('request_conflict');
		if (index(['diagnostic_run','diagnostic_packages'],method)>=0 && io.now()<next_probe) return error('rate_limited');
		if (length(filter(jobs,j=>j.sid == sid && j.finished == null)) >= 2) return error('busy');
		if (length(jobs) >= capacity) {
			let oldest = filter(jobs,j=>j.finished != null)[0];
			if (!oldest) return error('busy');
			jobs = filter(jobs,j=>j !== oldest);
		}
		let j = {id:io.random(),sid,method,args,request_id,digest,status:'queued',revision:1,deadline:io.now()+30000};
		push(jobs,j);
		if (index(['diagnostic_run','diagnostic_packages'],method)>=0) next_probe=io.now()+5000;
		// Start on the next event-loop turn so admission never waits for worker work.
		io.arm(1);
		return public_job(j);
		},callback);
	}
	function access(sid,id) {
		if (!job_token(sid) || !job_token(id)) return null;
		prune();
		return filter(jobs,j=>j.sid == sid && j.id == id)[0];
	}
	return {
		submit, pump,
		get:(sid,id,callback)=>{
			let j = access(sid,id);
			return !j ? deliver(error('job_expired'),callback) : authorized(sid,j.method,()=>public_job(j),callback);
		},
		cancel:(sid,id,callback)=>{
			let j = access(sid,id);
			if (!j) return deliver(error('job_expired'),callback);
			return authorized(sid,j.method,()=>{
			if (j.finished == null) {
				done(j,error('job_cancelled'),'cancelled');
				j.worker?.cancel();
				io.arm(1);
			}
			return public_job(j);
			},callback);
		}
	};
}
