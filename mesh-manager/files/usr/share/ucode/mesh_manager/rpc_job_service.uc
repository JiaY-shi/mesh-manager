// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import * as uloop from 'uloop';
import { connect } from 'ubus';
import { start } from 'mesh_process';
import { sha256 } from 'mesh_crypto';
import { now, boot, random, locked, load } from './durable.uc';
import { job_queue } from './rpc_jobs.uc';
import { job_scheduler } from './rpc_async.uc';

let queue, authorization_bus, pending_authorizations = 0;
function service() {
	if (queue) return queue;
	let memory = match(fs.readfile('/proc/meminfo') || '', /MemTotal:\s+([0-9]+) kB/),
		workers = memory && +memory[1] >= 256 * 1024 ? 2 : 1;
	queue = job_queue({
		boot:boot(),workers,now:()=>int(now()*1000),random:()=>random(16),digest:sha256,
		local_id:()=>locked(()=>load('identity.json')?.id,5),
		authorize:(sid,method,done)=>{
			// session lives in this same rpcd process: a synchronous call would
			// deadlock its event loop. Keep both ACL admission and renewal async.
			if (pending_authorizations >= 16) { done(false);return; }
			authorization_bus ??= connect(null,1);
			pending_authorizations++;
			let request, completed=false;
			function finish(allowed) {
				if(completed)return;completed=true;pending_authorizations--;done(allowed);
			}
			let diagnostic={diagnostic_run:'run',diagnostic_packages:'packages'};
			try { request=authorization_bus?.defer('session','access',{ubus_rpc_session:sid,
				scope:'ubus',object:diagnostic[method]?'mesh-manager.diag':'mesh-manager',
				function:diagnostic[method] || method},(code,result)=>{
				finish(code===0 && result?.access===true);
			}); } catch(ignored) {}
			if(!request) finish(false);
		},
		spawn:(method,args,budget,done)=>start(['/usr/bin/ucode','/usr/libexec/mesh-manager-rpc-worker',method],
			sprintf('%J',args),budget,done),
		arm:job_scheduler(uloop,()=>queue.pump())
	});
	return queue;
}

export function job_call(method, request) {
	let args = request?.args || {}, sid = args.ubus_rpc_session;
	if (method=='diagnostic_run' && length(filter(keys(args), key =>
		index(['check','node_id','request_id','ubus_rpc_session'],key)<0)))
		return {ok:false,error:{code:'invalid_request',message:'Unknown diagnostic argument'}};
	if (method=='diagnostic_packages' && length(filter(keys(args),key=>index(['request_id','ubus_rpc_session'],key)<0)))
		return {ok:false,error:{code:'invalid_request',message:'Unknown package inspection argument'}};
	// uhttpd supplies this session field after authentication. The Unix-root CLI
	// can still use existing methods; it cannot guess another browser's job ID.
	let deferred=request.defer();
	function reply(value) { try { request.reply(value); } catch(ignored) {} }
	if (method == 'repair_preview') service().submit(sid,method,{},args.request_id,reply);
	if (method == 'local_overrides_preview') service().submit(sid,method,{local:args.local},args.request_id,reply);
	if (method == 'diagnostic_run') service().submit(sid,method,{check:args.check,node_id:args.node_id},args.request_id,reply);
	if (method == 'diagnostic_packages') service().submit(sid,method,{},args.request_id,reply);
	if (method == 'job_get') service().get(sid,args.job_id,reply);
	if (method == 'job_cancel') service().cancel(sid,args.job_id,reply);
	return deferred;
}
