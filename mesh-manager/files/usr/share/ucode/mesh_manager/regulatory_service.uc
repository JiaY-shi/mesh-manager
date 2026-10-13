// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import { cursor } from 'uci';
import { connect } from 'ubus';
import { uci_sections } from 'mesh_data';
import { run } from 'mesh_process';
import { boot, now, locked, load } from './durable.uc';
import { radio_targets } from './radio_diagnostics.uc';
import { regulatory_binding } from './regulatory_worker.uc';
import { local_regulatory } from './regulatory_diagnostics.uc';

function monotonic() { return int(now()*1000); }
function remaining(deadline) { if(deadline-monotonic()<1000)die('request_timeout: Regulatory observation exceeded its deadline'); }
function capture(deadline,phase) {
	remaining(deadline);
	let wireless=locked(()=>{
		let c=cursor('/etc/config','/var/run/mesh-manager-uci','');
		if(!c.load('wireless'))die('backend_unavailable: Wireless configuration is unavailable');
		return uci_sections(c.get_all('wireless'));
	},5),connection,netifd;
	remaining(deadline);
	try { connection=connect(null,1);netifd=connection?.call('network.wireless','status',{}); }catch(e) {}
	connection?.disconnect();remaining(deadline);
	if(type(netifd)!='object')die('backend_unavailable: Actual wireless mapping is unavailable');
	let snapshot={wireless,netifd,bindings:{}};
	for(let target in radio_targets(snapshot).radios)for(let iface in target.interfaces) {
		remaining(deadline);let binding=regulatory_binding(iface.ifname,{read:fs.readfile,stat:fs.stat,readlink:fs.readlink});
		if(binding)snapshot.bindings[iface.ifname]=binding;
	}
	remaining(deadline);return snapshot;
}
export function local_regulatory_check(args) {
	return local_regulatory(args,{now:monotonic,time,boot,run,snapshot:capture,
		identity:()=>locked(()=>load('identity.json'),5)});
}
