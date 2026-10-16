// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { now, boot } from './durable.uc';
import * as durable from './durable.uc';
import { presence } from './advanced.uc';
import { run } from 'mesh_process';
import { node_ping, node_trace, local_dns, local_address_conflict } from './active_diagnostics.uc';
import { connect } from 'ubus';
import { radio_check } from './radio_service.uc';
import { local_regulatory_check } from './regulatory_service.uc';
import { upstream_dns_check } from './upstream_dns_service.uc';

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
