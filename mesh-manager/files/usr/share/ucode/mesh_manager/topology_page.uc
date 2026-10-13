// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { canonical, valid_text } from './model.uc';
import { effective_settings } from './local_settings.uc';
import { history_pager } from './history_page.uc';
import { sha256 } from 'mesh_crypto';

export const NODE_FIELDS = ['id','name','role','gateway','local','mesh_enabled','online',
	'management_address','address_source','management_up','addresses_complete','backhaul','stale'];
export const LINK_FIELDS = ['id','controller_id','node_id','kind','mesh_enabled','online',
	'active','wired_verified','wireless_verified','signal_dbm','phy_rate_mbps','stale'];
export const DETAIL_FIELDS = [...NODE_FIELDS,'model','network_id','controller_id',
	'cluster_version','local_version','drift_count','management_addresses','observation_age_ms',
	'wired_verified','wireless_verified','signal_dbm','phy_rate_mbps'];

function invalid() { die('invalid_request: Invalid topology request'); }
function corrupt() { die('corrupt_state: Invalid topology source'); }
function encode(value) { return sprintf('%J',canonical(value)); }
function identifier(value) {
	return type(value)=='string' && match(value,/^[0-9a-f]{32}$/)!=null;
}
function text(value,maximum) { return valid_text(value,1,maximum) ? value : null; }
function number(value,maximum) {
	return type(value)=='int' && value>=0 && value<=maximum ? value : null;
}
function boolean(value) { return type(value)=='bool' ? value : null; }
function ipv4(value) {
	if (type(value)!='string' || length(value)>15) return false;
	let parts=split(value,'.');
	if (length(parts)!=4) return false;
	for (let part in parts) {
		if (!length(part) || length(part)>3 || ''+int(part)!=part || int(part)<0 || int(part)>255) return false;
	}
	return int(parts[0])>0 && int(parts[0])<224 && int(parts[0])!=127;
}
function addresses(management) {
	let raw=type(management)=='object' ? management.addresses : null,values=[];
	if (type(raw)!='array') return {values,complete:false};
	// The existing netifd/report source supplies IPv4 addresses. Do not promote
	// an intent address or an unparsed string into an observed address. Aliases
	// are not capped at the source: inspect at most eight rows and retain their
	// valid subset, marking a truncated or damaged observation incomplete.
	let complete=length(raw)<=8;
	for (let row in slice(raw,0,8)) {
		if (type(row)!='object' || !ipv4(row.address) || index(values,row.address)>=0) {
			complete=false;continue;
		}
		push(values,row.address);
	}
	return {values,complete};
}
function freshness(seen,boot,stamp) {
	if (type(seen)!='object' || type(seen.boot)!='string' ||
		index(['int','double'],type(seen.seen))<0 || seen.seen<0)
		return {online:null,age:null};
	if (seen.boot!=boot) return {online:false,age:null};
	if (seen.seen>stamp) return {online:null,age:null};
	return {online:stamp-seen.seen<15,age:int((stamp-seen.seen)*1000)};
}
function path_values(path,usable) {
	let active=usable && index(['wired','wireless','none'],path?.active)>=0 ? path.active : null,
		quality=usable ? path?.quality : null;
	return {active,wired_verified:usable ? boolean(path?.wired) : null,
		wireless_verified:usable ? boolean(path?.wireless) : null,
		signal_dbm:type(quality?.signal_dbm)=='int' && quality.signal_dbm>=-127 && quality.signal_dbm<=0 ? quality.signal_dbm : null,
		phy_rate_mbps:index(['int','double'],type(quality?.phy_rate_mbps))>=0 && quality.phy_rate_mbps>0 && quality.phy_rate_mbps<=100000 ? quality.phy_rate_mbps : null};
}
function project(item,fields) {
	let result={};
	for (let field in fields) result[field]=item[field] ?? null;
	return result;
}
function fields(args,allowlist) {
	let selected=args.fields;
	if (selected==null || type(selected)=='array' && !length(selected)) return sort([...allowlist]);
	if (type(selected)!='array' || length(selected)>length(allowlist) ||
		length(uniq(selected))!=length(selected) ||
		length(filter(selected,field=>type(field)!='string' || index(allowlist,field)<0))) invalid();
	return sort([...selected]);
}

// io.frame captures identity/local/cluster together. observation is the current
// public local netifd/backhaul observation; presence contains existing volatile
// authenticated connection receipts. report_observations contains separately
// verified report receipts; a connection heartbeat cannot renew old telemetry.
// This module has no disk or network I/O.
export function topology_pages(io) {
	let cursor_key;
	return (method,args,sid) => {
		if (index(['nodes','links','detail'],method)<0 || type(args)!='object' ||
			length(filter(keys(args),key=>index(method=='detail' ?
				['node_id','fields','if_revision','ubus_rpc_session'] :
				['cursor','limit','fields','if_revision','ubus_rpc_session'],key)<0)) ||
			type(sid)!='string' || !match(sid,/^[0-9a-f]{32}$/)) invalid();
		let selected=fields(args,method=='detail' ? DETAIL_FIELDS : method=='nodes' ? NODE_FIELDS : LINK_FIELDS),
			conditional=args.if_revision ?? '';
		if (type(conditional)!='string' || conditional && !match(conditional,/^[0-9a-f]{64}$/) ||
			method=='detail' && !identifier(args.node_id)) invalid();
		if (method!='detail' && (type(args.limit ?? 10)!='int' || (args.limit ?? 10)<1 || (args.limit ?? 10)>50 ||
			type(args.cursor ?? '')!='string' || length(args.cursor ?? '')>4096)) invalid();
		let frame=io.frame(method,args),identity=frame?.identity,local=frame?.local,cluster=frame?.cluster,
			stamp=io.now(),boot=io.boot(),nodes=[],links=[],details={},authorization=[];
		if (type(identity)!='object' || !identifier(identity.id) ||
			index(['unbound','root','ap'],identity.role)<0 ||
			type(local)!='object' && local!=null || type(cluster)!='object' && cluster!=null ||
			index(['int','double'],type(stamp))<0 || stamp<0 || type(boot)!='string' || !length(boot)) corrupt();
		let network_id=identity.role=='ap' ? identity.binding?.network_id : identity.role=='root' ? identity.network_id : null,
			controller_id=identity.role=='root' ? identity.id : identity.role=='ap' ? identity.binding?.controller_id : null;
		if (identity.role!='unbound' && (!identifier(network_id) || !identifier(controller_id)) ||
			identity.role=='ap' && controller_id==identity.id) corrupt();
		let enabled=!!local?.intent && local.paused!==true,observation=frame.observation,
			settings=effective_settings(identity,local),management=observation?.management,
			local_address_result=addresses(management),local_addresses=local_address_result.values,
			local_path=path_values(observation?.backhaul,enabled),
			local_node={id:identity.id,name:text(settings?.name,64) || text(observation?.board?.hostname,64) || text(identity.name,64),
				role:identity.role,gateway:identity.role=='root' && index(['router','bridge'],identity.gateway)>=0 ? identity.gateway : null,
				local:true,mesh_enabled:enabled,online:true,management_address:local_addresses[0] || null,
				address_source:length(local_addresses) ? 'actual' : 'unknown',management_up:boolean(management?.up),
				addresses_complete:local_address_result.complete,
				backhaul:local_path.active,stale:!local_address_result.complete || management?.up!==true ||
					identity.role=='ap' && enabled && local_path.active==null};
		function add(node,extra) {
			push(nodes,node);
			details[node.id]={...node,...extra};
		}
		function link(node,path) {
			push(links,{id:sha256(controller_id+':'+node.id),controller_id,node_id:node.id,kind:'controller_ap',
				mesh_enabled:node.mesh_enabled,online:node.online,...path,stale:node.stale});
		}
		let local_extra={model:text(observation?.board?.model,256),network_id:network_id || null,controller_id,
			cluster_version:number(identity.role=='root' ? cluster?.version : identity.cluster_version,2147483647),
			local_version:number(local?.version,2147483647),drift_count:null,management_addresses:local_addresses,
			observation_age_ms:observation ? 0 : null,...local_path};
		if (identity.role=='ap') {
			let paired=ipv4(identity.binding.address) ? identity.binding.address : null,
				controller={id:controller_id,name:null,role:'root',gateway:null,local:false,mesh_enabled:null,online:null,
					management_address:paired,address_source:paired ? 'paired' : 'unknown',management_up:null,
					addresses_complete:false,backhaul:null,stale:true};
			add(controller,{model:null,network_id,controller_id,cluster_version:null,local_version:null,drift_count:null,
				management_addresses:paired ? [paired] : [],observation_age_ms:null,...path_values(null,false)});
		}
		add(local_node,local_extra);
		if (identity.role=='root') {
			let members=cluster?.members;
			if (type(members)!='object' || length(keys(members))>64) corrupt();
			for (let id in sort(keys(members))) {
				let member=members[id];
				if (type(member)!='object' || !identifier(id) || id==identity.id || type(member.authorized)!='bool') corrupt();
				if (member.authorized!==true) continue;
				if (member.id!=null && member.id!=id || member.certificate!=null &&
					(type(member.certificate)!='string' || length(member.certificate)>16384)) corrupt();
				push(authorization,{id,certificate:member.certificate || null});
				// An unavailable observation cannot invalidate another member's
				// detail. Authorization and identity validation above stay strict.
				let report=type(member.report)=='object' ? member.report : null;
				let fresh=freshness(frame.presence?.[id] || member,boot,stamp),
					observed=freshness(report ? frame.report_observations?.[id] : null,boot,stamp),
					current=fresh.online===true && observed.online===true,remote_management=report?.management,
					remote_address_result=addresses(remote_management),remote_addresses=remote_address_result.values,
					remote_enabled=member.mesh_paused===true ? false : boolean(report?.mesh_enabled),
					path=path_values(report?.backhaul,current && remote_enabled===true),
					node={id,name:text(member.name,64),role:'ap',gateway:null,local:false,mesh_enabled:remote_enabled,
						online:fresh.online,management_address:remote_addresses[0] || null,
						address_source:!length(remote_addresses) ? 'unknown' : current ? 'actual' : 'last_reported',
						management_up:current ? boolean(remote_management?.up) : null,
						addresses_complete:remote_address_result.complete,backhaul:path.active,
						stale:!remote_address_result.complete || !current || remote_management?.up!==true ||
							remote_enabled===true && path.active==null};
				add(node,{model:text(report?.model,256),network_id,controller_id,
					cluster_version:number(member.version,2147483647),local_version:number(report?.local_version,2147483647),
					drift_count:type(report?.drift)=='array' && length(report.drift)<=2048 ? length(report.drift) : null,
					management_addresses:remote_addresses,observation_age_ms:observed.age,...path});
				link(node,path);
			}
		} else if (identity.role=='ap') link(local_node,local_path);
		let scope=sha256(encode({id:identity.id,role:identity.role,network_id:network_id || null,controller_id,
			authorization,identity_fingerprint:identity.fingerprint || null,
			paired:identity.role=='ap' ? {address:identity.binding.address || null,port:identity.binding.port || null,
				ca_fingerprint:identity.binding.ca_fingerprint || null,key_epoch:identity.binding.key_epoch ?? null} : null}));
		if (method=='detail') {
			let item=details[args.node_id];
			if (!item) die('not_found: Node is not in the authorized topology');
			let stable=project(item,filter(DETAIL_FIELDS,field=>field!='observation_age_ms')),
				revision=sha256(encode({boot,scope,node_id:args.node_id,fields:selected,item:stable})),
				result={node_id:args.node_id,boot_id:boot,revision,observed_uptime_ms:int(stamp*1000),
					stale:item.stale,unchanged:conditional==revision};
			if (!result.unchanged) result.item=project(item,selected);
			return result;
		}
		// The shared stateless pager binds all public snapshot fields, query,
		// session, boot, network and authorization scope. Age alone is metadata;
		// address, status, path and membership changes expire prior page cursors.
		let records=method=='nodes' ? nodes : links,
			page=history_pager({now:()=>stamp,boot:()=>boot,random:()=>cursor_key ??= io.random(32),
				records:()=>reverse([...records])},{fields:{[method]:method=='nodes' ? NODE_FIELDS : LINK_FIELDS},
				maximum:method=='nodes' ? 65 : 64,scope}),
			result=page({...args,group:method,limit:args.limit ?? 10},sid);
		result.stale=length(filter(records,record=>record.stale))>0;
		result.volatile=true;
		return result;
	};
}
