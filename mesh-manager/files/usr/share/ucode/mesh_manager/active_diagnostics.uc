// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal } from './model.uc';
import { private_address } from './identity.uc';
import { job_token } from './rpc_jobs.uc';

function unavailable(message) { die('target_unavailable: ' + message); }
function address(value) {
	return private_address(value) && join('.',map(split(value,'.'),part=>''+int(part)))==value;
}
export function diagnostic_target(frame, id, now, boot) {
	if (!job_token(id)) die('invalid_request: Invalid diagnostic target');
	let identity=frame?.identity,local=frame?.local;
	if (!local?.intent || local.paused===true) unavailable('Enable Mesh before checking managed nodes');
	let target;
	if (identity?.role=='ap') {
		let binding=identity.binding;
		if (id!=binding?.controller_id || !address(binding.address)) unavailable('Controller binding is unavailable');
		target={id,address:binding.address,binding};
	} else if (identity?.role=='root') {
		let member=frame.cluster?.members?.[id],seen=frame.presence?.[id] || member;
		if (member?.authorized!==true || member.mesh_paused===true || member.report?.mesh_enabled===false ||
			seen?.boot!=boot || type(seen.seen)!='int' && type(seen.seen)!='double' || now<seen.seen || now-seen.seen>=15)
			unavailable('Node is not currently online and managed');
		let management=member.report?.management,addresses=management?.addresses;
		if (management?.up!==true || type(addresses)!='array' || !length(addresses) || length(addresses)>8 ||
			!address(addresses[0]?.address)) unavailable('Node management address is unavailable');
		target={id,address:addresses[0].address,certificate:member.certificate || null};
	} else unavailable('Device is not enrolled');
	return {...target,identity:identity.id,role:identity.role,network_id:identity.network_id || identity.binding?.network_id,boot};
}
export function ping_result(result) {
	if (result?.code==-2) die('request_timeout: Node check exceeded its deadline');
	if (index([0,1],result?.code)<0 || type(result.stdout)!='string' || length(result.stdout)>4096)
		die('backend_unavailable: Ping is unavailable');
	let packets=match(result.stdout,/(^|\n)([0-9]+) packets transmitted, ([0-9]+) packets received, (([0-9]+) duplicates, )?([0-9]+)% packet loss(\n|$)/),
		rtt=match(result.stdout,/(^|\n)round-trip min\/avg\/max = ([0-9]+\.[0-9]+)\/([0-9]+\.[0-9]+)\/([0-9]+\.[0-9]+) ms(\n|$)/);
	if (!packets) die('backend_unavailable: Ping returned an unsupported result');
	let sent=int(packets[2]),received=int(packets[3]),duplicates=int(packets[5] || '0');
	if (sent<1 || sent>3 || received<0 || received>sent || duplicates<0 || duplicates>65535 ||
		duplicates && !received || int(packets[6])!=int(100*(sent-received)/sent) || result.code!=(received<3 ? 1 : 0))
		die('backend_unavailable: Ping returned inconsistent counters');
	let roundtrip=rtt ? {minimum:+rtt[2],average:+rtt[3],maximum:+rtt[4]} : null;
	if (received>0 && (!roundtrip || roundtrip.minimum>roundtrip.average || roundtrip.average>roundtrip.maximum || roundtrip.maximum>5000) || !received && roundtrip)
		die('backend_unavailable: Ping returned inconsistent timing');
	return {status:duplicates?'duplicate_replies':received==sent && sent==3?'reachable':received>0?'partial':'no_reply',transmitted:sent,received,duplicates,
		loss_percent:100.0*(sent-received)/sent,roundtrip_ms:roundtrip};
}
function run_check(args, io, check, command, parse) {
	if (type(args)!='object' || length(keys(args))!=2 || args.check!=check || !job_token(args.node_id))
		die('invalid_request: Invalid node check arguments');
	let before=diagnostic_target(io.frame(),args.node_id,io.now(),io.boot());
	let result=io.run(['/bin/busybox',...command,before.address],'',7000);
	let after=diagnostic_target(io.frame(),args.node_id,io.now(),io.boot());
	if (!equal(before,after)) die('target_changed: Node binding or management address changed during the check');
	return {...parse(result,before.address),node_id:before.id,address:before.address,observed_at:io.time()};
}
export function node_ping(args, io) {
	return run_check(args,io,'node_ping',['ping','-4','-q','-c','3','-W','1','-w','5'],ping_result);
}
function trace_invalid() { die('backend_unavailable: Traceroute returned an unsupported result'); }
function hop_address(value) {
	if (type(value)!='string' || !match(value,/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)) return false;
	return !length(filter(split(value,'.'),part=>length(part)>3 || int(part)>255 || ''+int(part)!=part));
}
export function trace_result(result, target) {
	if (result?.code==-2) die('request_timeout: Node check exceeded its deadline');
	if (result?.code!=0 || type(result.stdout)!='string' || length(result.stdout)>4096 ||
		index(result.stdout,'\u0000')>=0 || match(result.stdout,/[^\t\n -~]/) || !address(target)) trace_invalid();
	let lines=split(trim(result.stdout),'\n'),header=match(lines[0] || '',/^traceroute to ([0-9.]+) \(([0-9.]+)\), 5 hops max, ([0-9]+) byte packets$/);
	if (!header || header[1]!=target || header[2]!=target || int(header[3])<28 || int(header[3])>65535 || length(lines)<2 || length(lines)>6) trace_invalid();
	let hops=[],terminal=false;
	for (let line in slice(lines,1)) {
		let fields=split(replace(trim(line),/[ \t]+/g,' '),' '),number=length(hops)+1;
		if (terminal || fields[0]!=''+number) trace_invalid();
		if (length(fields)==2 && fields[1]=='*') {
			push(hops,{hop:number,address:null,roundtrip_ms:null,status:'no_reply'});continue;
		}
		if (length(fields)<4 || length(fields)>5 || !hop_address(fields[1]) ||
			!match(fields[2],/^[0-9]+\.[0-9]+$/) || +fields[2]>7000 || fields[3]!='ms') trace_invalid();
		let annotation=fields[4],reason=null,status='reply';
		if (annotation && annotation!='!') {
			let reasons={'!N':'network_unreachable','!H':'host_unreachable','!P':'protocol_unreachable',
				'!S':'source_route_failed','!A':'prohibited','!C':'prohibited','!V':'prohibited',
				'!U':'unknown_destination','!I':'isolated','!T':'tos_unreachable'};
			reason=reasons[annotation];
			let mtu=match(annotation,/^!F-([0-9]+)$/),code=match(annotation,/^!<([0-9]+)>$/);
			if (mtu && int(mtu[1])<=65535) reason='fragmentation_needed';
			if (code && int(code[1])<=255) reason='unreachable';
			if (!reason) trace_invalid();
			status='unreachable';terminal=true;
		} else if (annotation=='!') terminal=true;
		push(hops,{hop:number,address:fields[1],roundtrip_ms:+fields[2],status,reason});
	}
	let last=hops[length(hops)-1];
	// Numeric ICMP source is an observation, not authenticated identity or proof of service health.
	return {status:last.status=='unreachable'?'unreachable':last.address==target?'target_reply':length(hops)==5?'hop_limit':'incomplete',
		maximum_hops:5,hops};
}
export function node_trace(args, io) {
	return run_check(args,io,'node_trace',['traceroute','-4','-n','-m','5','-q','1','-w','1'],trace_result);
}

// Fixed loopback query: this checks the local resolver only, not upstream DNS.
export function dns_result(result) {
	if (result?.code==-2) die('request_timeout: Local DNS check exceeded its deadline');
	if (index([0,1],result?.code)<0 || type(result.stdout)!='string' || length(result.stdout)>4096 ||
		index(result.stdout,'\u0000')>=0 || match(result.stdout,/[^\t\r\n -~]/))
		die('backend_unavailable: DNS command returned an unsupported result');
	let text=replace(trim(result.stdout),/[\t ]+/g,' '),
		lines=filter(split(replace(text,'\r',''),'\n'),line=>length(line)>0);
	if (result.code==1 && equal(lines,[';; connection timed out; no servers could be reached']))
		return {status:'no_reply',addresses:[]};
	if (length(lines)<3 || lines[0]!='Server: 127.0.0.1' || lines[1]!='Address: 127.0.0.1:53')
		die('backend_unavailable: DNS resolver output does not match the fixed query');
	let answer=slice(lines,2);
	if (answer[0]=='Non-authoritative answer:') shift(answer);
	if (result.code==1 && (equal(answer,["** server can't find localhost: NXDOMAIN"]) ||
		equal(answer,["** server can't find localhost.: NXDOMAIN"])))
		return {status:'record_missing',addresses:[]};
	if (result.code!=0 || length(answer)<2 || length(answer)>16 || length(answer)%2)
		die('backend_unavailable: DNS answer is incomplete or unsupported');
	let addresses=[];
	for (let n=0;n<length(answer);n+=2) {
		let line=answer[n+1];
		if (index(['Name: localhost','Name: localhost.'],answer[n])<0 ||
			index(line,'Address: ')!=0 || !hop_address(substr(line,9)))
			die('backend_unavailable: Invalid DNS answer address');
		push(addresses,substr(line,9));
	}
	if (length(uniq(addresses))!=length(addresses)) die('backend_unavailable: Duplicate DNS answer');
	return {status:length(filter(addresses,a=>index(a,'127.')!=0)) ? 'unexpected_answer' : 'answered',addresses};
}
export function local_dns(args, io) {
	if (type(args)!='object' || length(keys(args))!=2 || args.check!='local_dns' || !job_token(args.node_id))
		die('invalid_request: Invalid local DNS check arguments');
	let identity=io.identity(),boot=io.boot();
	if (identity?.id!=args.node_id) unavailable('Local device identity changed');
	let result=io.run(['/bin/busybox','nslookup','-type=A','-retry=1','-timeout=2','localhost.','127.0.0.1'],'',4000);
	if (io.identity()?.id!=identity.id || io.boot()!=boot)
		die('target_changed: Local device identity changed during the check');
	return {...dns_result(result),node_id:identity.id,resolver:'127.0.0.1',query:'localhost.',
		query_type:'A',scope:'local_resolver',observed_at:io.time()};
}

function local_management_target(args, io, changed) {
	let identity=io.identity(),current_boot=io.boot(),code=changed?'target_changed':'target_unavailable';
	if (type(identity)!='object' || identity.id!=args.node_id || !job_token(identity.id) ||
		type(current_boot)!='string' || !length(current_boot))
		die(code+': Local device identity is unavailable or changed');
	// netifd is queried outside the durable lock. Neither the UCI intent nor a
	// saved pairing address can select the target of this local ARP check.
	let management=io.management(),device=management?.l3_device,addresses=management?.['ipv4-address'],primary=addresses?.[0]?.address;
	if (management?.up!==true || type(device)!='string' || !length(device) || length(device)>15 ||
		type(addresses)!='array' || !hop_address(primary)) die(code+': Actual LAN management address is unavailable or changed');
	for (let n=0;n<length(device);n++) if (index('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-',substr(device,n,1))<0)
		die(code+': Actual LAN device is unsupported');
	let parts=split(primary,'.');
	if (int(parts[0])==0 || int(parts[0])==127 || int(parts[0])>=224)
		die(code+': Actual LAN address is not a unicast IPv4 address');
	return {identity:clone(identity),boot:current_boot,device,address:primary,up:true};
}
export function address_conflict_result(result) {
	if (result?.code==-2) die('request_timeout: Local address check exceeded its deadline');
	if (index([0,1],result?.code)<0 || type(result.stdout)!='string' || !length(result.stdout) || length(result.stdout)>1024)
		die('backend_unavailable: Address check returned an unsupported result');
	let value;
	try { value=json(result.stdout); } catch(e) { die('backend_unavailable: Address check returned incomplete JSON'); }
	if (type(value)!='object' || type(value.schema)!='int' || value.schema!=1)
		die('backend_unavailable: Address check returned an unsupported schema');
	if (value.status=='unavailable') {
		if (result.code!=1 || length(keys(value))!=3 || type(value.reason)!='string' ||
			index(['target_changed','socket_unavailable','interface_unavailable','send_failed','receive_limit','receive_failed','budget_exceeded'],value.reason)<0)
			die('backend_unavailable: Address check returned an unsupported failure');
		die((value.reason=='target_changed'?'target_changed':value.reason=='budget_exceeded'?'request_timeout':'backend_unavailable')+': Local address check could not complete');
	}
	if (result.code!=0 || length(keys(value))!=4 ||
		index(['no_conflict_observed','conflict_observed'],value.status)<0 ||
		type(value.transmitted)!='int' || value.transmitted!=2 || type(value.claims)!='int' || value.claims<0 || value.claims>=512 ||
		(value.status=='no_conflict_observed')!=(value.claims==0))
		die('backend_unavailable: Address check returned inconsistent counters');
	return {status:value.status,transmitted:value.transmitted,claims:value.claims};
}
export function local_address_conflict(args, io) {
	if (type(args)!='object' || length(keys(args))!=2 || args.check!='local_address_conflict' || !job_token(args.node_id))
		die('invalid_request: Invalid local address check arguments');
	let before=local_management_target(args,io,false),
		result=io.run(['/usr/libexec/mesh-manager-arp-probe',before.device,before.address],'',4000),
		after=local_management_target(args,io,true);
	if (!equal(before,after)) die('target_changed: Local device identity or actual LAN management address changed during the check');
	return {...address_conflict_result(result),node_id:before.identity.id,address:before.address,
		scope:'local_primary_ipv4',observed_at:io.time()};
}
