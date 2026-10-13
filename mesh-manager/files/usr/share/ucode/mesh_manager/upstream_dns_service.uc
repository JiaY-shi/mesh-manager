// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { connect } from 'ubus';
import { run } from 'mesh_process';
import { now, boot, locked, load } from './durable.uc';
import { local_upstream_dns } from './upstream_dns.uc';

function monotonic() { return int(now()*1000); }
function snapshot(deadline) {
	if(monotonic()>=deadline)die('request_timeout: Runtime DNS observation exceeded its deadline');
	let connection,value=null;
	try { connection=connect(null,1);value=connection?.call('network.interface','dump',{}); }catch(e){}
	connection?.disconnect();
	if(monotonic()>=deadline)die('request_timeout: Runtime DNS observation exceeded its deadline');
	if(type(value)!='object')die('backend_unavailable: Runtime DNS candidates are unavailable');
	return value;
}
export function upstream_dns_check(args) {
	return local_upstream_dns(args,{now:monotonic,time,boot,run,snapshot,
		identity:()=>locked(()=>load('identity.json'),5)});
}
