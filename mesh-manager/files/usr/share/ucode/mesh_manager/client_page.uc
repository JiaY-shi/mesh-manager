// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { effective_settings } from './local_settings.uc';
import { history_pager } from './history_page.uc';
import { sha256 } from 'mesh_crypto';
import { canonical } from './model.uc';
const CLIENT_FIELDS=['node_id','address','interface','authorized','signal'];
const EVENT_FIELDS=['kind','client','from','to','at'];

// Injected I/O keeps authorization, disabled-node and stale-sample behavior
// testable without fabricating clients on a production network.
export function client_pages(io) {
	let cursor_key;
	return (method,args,sid) => {
		if (index(['clients','history'],method)<0 || type(args)!='object' ||
			length(filter(keys(args),key=>index(['node_id','cursor','limit','fields','if_revision','ubus_rpc_session'],key)<0)))
			die('invalid_request: Invalid client page arguments');
		let filter_id=args.node_id ?? '';
		if (type(filter_id)!='string' || filter_id && !match(filter_id,/^[0-9a-f]{32}$/))
			die('invalid_request: Invalid client node filter');
		let frame=io.frame(),identity=frame.identity,stamp=io.now(),boot=io.boot(),nodes=[],allowed={},binding=[];
		function add(id,name,enabled,online,certificate) {
			if (!enabled) return;
			allowed[id]=true;push(nodes,{id,name,online});
			push(binding,{id,certificate});
		}
		let enabled=!!frame.local?.intent && frame.local.paused!==true;
		if (identity && index(['root','ap'],identity.role)>=0 && enabled) {
			add(identity.id,effective_settings(identity, frame.local)?.name || identity.name || identity.id,true,true,null);
			if (identity.role=='root') for (let id in sort(keys(frame.cluster?.members || {}))) {
				let member=frame.cluster.members[id],seen=io.presence(id) || member;
				add(id,member.name || id,member.authorized===true && member.mesh_paused!==true && member.report?.mesh_enabled!==false,
					seen.boot==boot && stamp>=seen.seen && stamp-seen.seen<15,member.certificate || null);
			}
		}
		if (length(nodes)>65) die('clients_unavailable: Too many observation sources');
		if (filter_id && !allowed[filter_id]) die('not_found: Node is not an enabled managed observation source');
		let observations=enabled ? io.observations() : {nodes:{},samples:{},events:[]},records=[];
		for (let node in nodes) {
			let sample=observations.samples[node.id];
			node.available=node.online && sample!=null;
			node.age_ms=sample?.age_ms ?? null;
			if (method!='clients' || !node.available || filter_id && filter_id!=node.id) continue;
			for (let client in observations.nodes[node.id] || []) push(records,{node_id:node.id,...client});
		}
		if (method=='clients')
			// history_pager reverses records, so sort backwards for stable ascending display.
			records=sort(records,(a,b)=>a.node_id+a.address < b.node_id+b.address ? 1 : -1);
		else records=filter(observations.events,row=>(row.from==null || allowed[row.from]) && (row.to==null || allowed[row.to]) &&
			(!filter_id || row.from==filter_id || row.to==filter_id));
		let page=history_pager({now:()=>stamp,boot:()=>boot,random:()=>cursor_key ??= io.random(32),records:()=>records},
			{fields:{clients:CLIENT_FIELDS,history:EVENT_FIELDS},maximum:method=='clients'?65*128:128,
				cursor_fields:method=='clients'?['node_id','address','interface','authorized']:null,
				scope:sha256(sprintf('%J',canonical({node_id:filter_id,network_id:identity?.network_id,binding})))});
		let query={...args,group:method};delete query.node_id;
		let result=page(query,sid);
		result.nodes=nodes;result.node_id=filter_id;result.volatile=true;
		result.stale=method=='clients' && length(filter(nodes,n=>(!filter_id || n.id==filter_id) && !n.available))>0;
		return result;
	};
}
