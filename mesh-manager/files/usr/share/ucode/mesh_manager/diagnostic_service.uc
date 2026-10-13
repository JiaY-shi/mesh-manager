// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { event_read, event_clear } from './event_log.uc';
import { history_pager } from './history_page.uc';
import { now, boot, random } from './durable.uc';
import * as durable from './durable.uc';
import { presence } from './advanced.uc';
import { run } from 'mesh_process';
import { node_ping, node_trace, local_dns, local_address_conflict } from './active_diagnostics.uc';
import * as fs from 'fs';
import { connect } from 'ubus';
import { package_inventory } from './package_inventory.uc';
import { radio_check } from './radio_service.uc';
import { local_regulatory_check } from './regulatory_service.uc';
import { upstream_dns_check } from './upstream_dns_service.uc';

export function package_check(args) {
	try { return {ok:true,data:package_inventory(args,{time,run,executable:path=>fs.access(path,'x')})}; }
	catch(e) {
		let found=match(''+e,/([a-z_]+): ([^\n]+)/);
		return {ok:false,error:{code:found?.[1] || 'internal_error',message:'Package inspection failed'}};
	}
}

export function active_check(args) {
	try {
		if(args?.check=='local_radios')return {ok:true,data:radio_check(args)};
		if(args?.check=='local_regulatory')return {ok:true,data:local_regulatory_check(args)};
		if(args?.check=='local_upstream_dns')return {ok:true,data:upstream_dns_check(args)};
		let check={node_ping,node_trace,local_dns,local_address_conflict}[args?.check];
		if (type(check)!='function') die('invalid_request: Unknown diagnostic check');
		let data=check(args,{now,boot,time,run,management:()=>{
			let connection,result=null;
			try { connection=connect(null,1);result=connection?.call('network.interface.lan','status',{}); }
			catch(e) {}
			connection?.disconnect();return result;
		},identity:()=>durable.locked(()=>durable.load('identity.json'),5),frame:()=>durable.locked(()=>{
			let identity=durable.load('identity.json'),local=durable.load('state.json'),cluster=durable.load('cluster.json'),seen={};
			if(identity?.role=='root' && cluster?.members?.[args.node_id]) seen[args.node_id]=presence(args.node_id);
			return {identity,local,cluster,presence:seen};
		},5)});
		return {ok:true,data};
	} catch(e) {
		let found=match(''+e,/([a-z_]+): ([^\n]+)/);
		return {ok:false,error:{code:found?.[1] || 'internal_error',message:found?.[2] || 'Node check failed'}};
	}
}

let cursor_key;
export function log_call(method,request) {
	try {
		let args=request?.args || {},sid=args.ubus_rpc_session || '00000000000000000000000000000000',
			allowed=method=='logs' ? ['cursor','limit','fields','if_revision','ubus_rpc_session'] : ['expected_revision','request_id','ubus_rpc_session'];
		if(type(args)!='object' || length(filter(keys(args),key=>index(allowed,key)<0)))die('invalid_request: Invalid runtime log arguments');
		let result;
		if(method=='clear_logs')result=event_clear(args.expected_revision,args.request_id,sid);
		else if(method=='logs') {
			let snapshot=event_read(),page=history_pager({now,boot,random:()=>cursor_key ??= random(32),records:()=>snapshot.records},
				{fields:{runtime:['id','component','status','version','timestamp']},maximum:128});
			result=page({...args,group:'runtime'},sid);
			result.clear_revision=snapshot.revision;
			result.volatile=true;result.capacity=128;
		} else die('invalid_request: Unknown runtime log method');
		return {ok:true,data:result};
	} catch(e) {
		let found=match(''+e,/([a-z_]+): ([^\n]+)/);
		return {ok:false,error:{code:found?.[1] || 'internal_error',message:found?.[2] || 'Runtime logs unavailable',retryable:found?.[1]=='busy'}};
	}
}
