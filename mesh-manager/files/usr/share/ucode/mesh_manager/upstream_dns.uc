// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal } from './model.uc';
import { job_token } from './rpc_jobs.uc';

const LIMIT=16, TEST_LIMIT=4, WHOLE_MS=12000, PROCESS_MS=1500;
const ANSWERS=['answered','empty_answer','formerr','servfail','nxdomain','notimp','refused','other_rcode','truncated_requires_tcp'];
const OBSERVATIONS=['no_reply','invalid_reply','network_unreachable','receive_limit'];
const FAILURES=['invalid_target','entropy_unavailable','clock_unavailable','socket_unavailable','send_failed','receive_failed','budget_exceeded'];

export function dns_ipv4(value) {
	if(type(value)!='string' || length(value)<7 || length(value)>15)return false;
	let parts=split(value,'.');if(length(parts)!=4)return false;
	for(let part in parts) {
		if(!length(part) || length(part)>3)return false;
		for(let n=0;n<length(part);n++)if(index('0123456789',substr(part,n,1))<0)return false;
		let number=int(part);if(number>255 || ''+number!=part)return false;
	}
	return true;
}
function name(value) {
	if(type(value)!='string' || !length(value) || length(value)>63)return false;
	for(let n=0;n<length(value);n++)if(index('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-',substr(value,n,1))<0)return false;
	return substr(value,0,1)!='.' && substr(value,0,1)!='-';
}
function ipv6_candidate(value) {
	if(type(value)!='string' || length(value)<2 || length(value)>64 || index(value,':')<0)return false;
	for(let n=0;n<length(value);n++)if(index('0123456789abcdefABCDEF:.%',substr(value,n,1))<0)return false;
	return true; // Classification only: IPv6 is never passed to the native helper.
}
function nonunicast(value) { let first=int(split(value,'.')[0]);return first==0 || first==127 || first>=224; }
function issue(issues,value) { if(index(issues,value)<0 && length(issues)<8)push(issues,value); }

// Return a bounded candidate observation, not proof of a process's DNS policy.
export function upstream_targets(snapshot) {
	let interfaces=snapshot?.interface,issues=[],locals=[],candidates=[],selected=[],excluded=[],seen={},limited=false;
	if(type(snapshot)!='object' || type(interfaces)!='array' || length(interfaces)>64 ||
		length(sprintf('%J',snapshot))>131072)
		return {candidates:[],selected:[],excluded:[],issues:['source_unavailable'],limited:true};
	for(let entry in interfaces) {
		if(type(entry)!='object' || !name(entry.interface) || type(entry.up)!='bool')
			return {candidates:[],selected:[],excluded:[],issues:['source_unavailable'],limited:true};
		if(seen[entry.interface])return {candidates:[],selected:[],excluded:[],issues:['source_unavailable'],limited:true};
		seen[entry.interface]=true;
		let addresses=entry['ipv4-address'];
		if(addresses!=null && (type(addresses)!='array' || length(addresses)>32))
			return {candidates:[],selected:[],excluded:[],issues:['source_unavailable'],limited:true};
		for(let row in addresses || []) {
			if(!dns_ipv4(row?.address))return {candidates:[],selected:[],excluded:[],issues:['source_unavailable'],limited:true};
			if(index(locals,row.address)<0)push(locals,row.address);
		}
	}
	for(let entry in interfaces) {
		if(!entry.up)continue;
		let servers=entry['dns-server'];
		if(servers==null)continue;
		if(type(servers)!='array')return {candidates:[],selected:[],excluded:[],issues:['source_unavailable'],limited:true};
		if(length(servers)>16){limited=true;issue(issues,'candidate_limit');}
		for(let value in slice(servers,0,16)) {
			if(!dns_ipv4(value)) {
				limited=true;issue(issues,ipv6_candidate(value)?'ipv6_not_covered':'invalid_candidate');continue;
			}
			let found=filter(candidates,row=>row.resolver==value)[0];
			if(found) {
				if(index(found.sources,entry.interface)<0) {
					if(length(found.sources)<8)push(found.sources,entry.interface);
					else {limited=true;issue(issues,'source_limit');}
				}
				continue;
			}
			if(length(candidates)>=LIMIT){limited=true;issue(issues,'candidate_limit');continue;}
			push(candidates,{resolver:value,sources:[entry.interface]});
		}
	}
	for(let row in candidates) {
		let status=nonunicast(row.resolver)?'nonunicast_candidate':
			index(locals,row.resolver)>=0?'local_candidate':length(selected)>=TEST_LIMIT?'not_tested_limit':null;
		if(status) { limited=true;issue(issues,status=='not_tested_limit'?'test_limit':status);push(excluded,{...row,status});continue; }
		push(selected,row);
	}
	if(!length(candidates) && !length(issues))issue(issues,'no_runtime_dns');
	return {candidates,selected,excluded,issues,limited};
}

// Bind every interface's address, candidate source and routing topology. Uptime,
// traffic counters and IPv6 lease lifetimes are observations, not IPv4 DNS target
// semantics. The complete original dump remains private; it is never projected.
export function upstream_binding(snapshot) {
	if(type(snapshot?.interface)!='array' || length(snapshot.interface)>64 || length(sprintf('%J',snapshot))>131072 ||
		length(filter(snapshot.interface,entry=>type(entry)!='object')))return null;
	function routes(value) {
		if(type(value)!='array')return clone(value);
		return map(value,row=>{
			let result=clone(row);
			// A countdown changes without a route change. Keep every other raw
			// route property, and bind removal at expiry in the next observation.
			if(type(result)=='object')for(let key in ['valid','preferred','expires'])delete result[key];
			return result;
		});
	}
	return map(snapshot.interface,entry=>{
		let result={};
		for(let key in ['interface','up','pending','available','autostart','dynamic','proto','device','l3_device',
			'metric','dns_metric','dns-metric','dns-server','dns-search','ipv4-address','route'])
			if(key in entry)result[key]=key=='route'?routes(entry[key]):clone(entry[key]);
		if(type(entry.inactive)=='object') {
			result.inactive={};
			for(let key in ['dns-server','dns-search','ipv4-address','route'])
				if(key in entry.inactive)result.inactive[key]=key=='route'?routes(entry.inactive[key]):clone(entry.inactive[key]);
		}
		return result;
	});
}

export function dns_probe_result(result) {
	if(result?.code==-2)return {status:'process_timeout',rcode:null,elapsed_ms:null};
	if(index([0,1],result?.code)<0 || type(result.stdout)!='string' || !length(result.stdout) || length(result.stdout)>1024)
		die('backend_unavailable: DNS probe returned unsupported output');
	let value;try { value=json(result.stdout); }catch(e){die('backend_unavailable: DNS probe returned incomplete JSON');}
	if(type(value)!='object' || length(keys(value))!=6 || value.schema!==1 ||
		index([...ANSWERS,...OBSERVATIONS,...FAILURES],value.status)<0 ||
		!(value.elapsed_ms===null || type(value.elapsed_ms)=='int' && value.elapsed_ms>=0 && value.elapsed_ms<=60000) ||
		type(value.transmitted)!='int' || value.transmitted<0 || value.transmitted>1 ||
		type(value.received)!='int' || value.received<0 || value.received>32)
		die('backend_unavailable: DNS probe returned invalid fields');
	let answer=index(ANSWERS,value.status)>=0,failure=index(FAILURES,value.status)>=0;
	if(result.code!=(failure?1:0) ||
		(answer && (type(value.rcode)!='int' || value.rcode<0 || value.rcode>15 || value.transmitted!=1 || value.received<1 ||
			value.elapsed_ms===null || value.elapsed_ms>=1250)) ||
		(!answer && value.rcode!==null) || (!failure && value.elapsed_ms===null) ||
		(!failure && value.status!='network_unreachable' && value.transmitted!=1) ||
		(value.status=='no_reply' && value.received!=0) ||
		(value.status=='invalid_reply' && (value.received<1 || value.received>=32)) ||
		(value.status=='receive_limit' && value.received!=32))
		die('backend_unavailable: DNS probe returned inconsistent counters');
	let codes={answered:0,empty_answer:0,formerr:1,servfail:2,nxdomain:3,notimp:4,refused:5};
	if((value.status in codes && value.rcode!=codes[value.status]) ||
		(value.status=='other_rcode' && value.rcode<6))die('backend_unavailable: DNS probe returned an inconsistent response code');
	return {status:value.status,rcode:value.rcode,elapsed_ms:value.elapsed_ms};
}

export function local_upstream_dns(args,io) {
	if(type(args)!='object' || length(keys(args))!=2 || args.check!='local_upstream_dns' || !job_token(args.node_id))
		die('invalid_request: Invalid runtime DNS check arguments');
	let started=io.now(),deadline=started+WHOLE_MS,identity=clone(io.identity()),boot=io.boot();
	if(identity?.id!=args.node_id || type(boot)!='string' || !length(boot))die('target_unavailable: Local device identity is unavailable or changed');
	function remaining() { if(io.now()>=deadline)die('request_timeout: Runtime DNS observation exceeded its deadline'); }
	remaining();let before=clone(io.snapshot(deadline,'before'));remaining();
	let target=upstream_targets(before),binding=upstream_binding(before),resolvers=[];
	function unchanged(phase) {
		remaining();let snapshot=io.snapshot(deadline,phase);remaining();
		if(!equal(binding,upstream_binding(snapshot)) || !equal(identity,io.identity()) || boot!=io.boot())
			die('target_changed: Runtime DNS candidates or local device identity changed during the check');
		remaining();
	}
	for(let row in target.selected) {
		unchanged('candidate');
		if(deadline-io.now()<PROCESS_MS)die('request_timeout: Runtime DNS observation exceeded its deadline');
		let observed=dns_probe_result(io.run(['/usr/libexec/mesh-manager-dns-probe',row.resolver],'',PROCESS_MS));
		remaining();push(resolvers,{resolver:row.resolver,sources:clone(row.sources),...observed});
	}
	unchanged('after');
	let answered=length(filter(resolvers,row=>row.status=='answered')),
		complete=length(resolvers)>0 && !target.limited && answered==length(resolvers);
	let result={schema:1,node_id:identity.id,scope:'runtime_netifd_dns',source:'netifd',query:'.',query_type:'NS',transport:'udp',
		observed_at:io.time(),status:complete?'complete':length(resolvers)?'partial':'unavailable',complete,
		limited:target.limited,candidate_count:length(target.candidates),tested_count:length(resolvers),issues:target.issues,
		excluded:target.excluded,resolvers};
	if(length(sprintf('%J',result))>65536)die('result_too_large: Runtime DNS observation exceeds its output limit');
	return result;
}
