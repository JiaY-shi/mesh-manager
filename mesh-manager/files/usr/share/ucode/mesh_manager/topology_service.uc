// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as durable from './durable.uc';
import { presence, observed_topology_report } from './advanced.uc';
import { topology_observation } from './runtime.uc';
import { topology_pages } from './topology_page.uc';

const pages=topology_pages({...durable,frame:(method,args)=>{
	let frame=durable.locked(()=>({identity:durable.load('identity.json'),local:durable.load('state.json'),
		cluster:durable.load('cluster.json')}),5),members=frame.cluster?.members || {},seen={},reports={};
	if(length(keys(members))>64)die('corrupt_state: Too many topology members');
	// Volatile observations are read after releasing the private-frame lock.
	if(frame.identity?.role=='root')for(let id in keys(members)) {
		let member=members[id];
		if(member?.authorized!==true)continue;
		seen[id]=presence(id);
		let sample=observed_topology_report(id,{controller_id:frame.identity.id,
			network_id:frame.identity.network_id,certificate:member.certificate || null},member.report);
		reports[id]=sample ? {boot:sample.boot,seen:sample.seen} : null;
		if((method=='links' || method=='detail' && args.node_id==id) && type(member.report?.backhaul)=='object') {
			member.report.backhaul={...member.report.backhaul,quality:sample?.quality || null};
		}
	}
	return {...frame,presence:seen,report_observations:reports,observation:topology_observation()};
}});
export function topology_call(method,request) {
	try {
		let args=request?.args || {};
		return {ok:true,data:pages(method,args,args.ubus_rpc_session || '00000000000000000000000000000000')};
	} catch(e) {
		let found=match(''+e,/([a-z_]+): ([^\n]+)/);
		return {ok:false,error:{code:found?.[1] || 'internal_error',message:found?.[2] || 'Topology unavailable',
			retryable:found?.[1]=='busy'}};
	}
}
