// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import { cursor } from 'uci';
import { connect } from 'ubus';
import { uci_sections } from 'mesh_data';
import { run } from 'mesh_process';
import { boot, now, locked, load } from './durable.uc';
import { local_radios, radio_targets, radio_observation } from './radio_diagnostics.uc';

function monotonic() { return int(now()*1000); }
function remaining(deadline) {
	if (deadline-monotonic()<1000) die('request_timeout: Radio observation exceeded its deadline');
}
function index_value(path) {
	let value=trim(fs.readfile(path) || '');
	if (!length(value) || length(value)>10) return null;
	for (let n=0;n<length(value);n++) if (index('0123456789',substr(value,n,1))<0) return null;
	let result=int(value);
	return result>=0 && result<=2147483647 && ''+result==value ? result : null;
}
function kernel_binding(ifname) {
	let path='/sys/class/net/'+ifname, ifindex=index_value(path+'/ifindex'),
		phyindex=index_value(path+'/phy80211/index'), link=fs.readlink(path+'/phy80211');
	if(ifindex==null || ifindex<1 || phyindex==null || type(link)!='string')return null;
	let parts=split(link,'/'),phy=parts[length(parts)-1];
	if(!length(phy) || length(phy)>63 || substr(phy,0,1)=='.' || substr(phy,0,1)=='-')return null;
	for(let n=0;n<length(phy);n++)if(index('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-',substr(phy,n,1))<0)return null;
	if(index_value(path+'/ifindex')!=ifindex || index_value(path+'/phy80211/index')!=phyindex || fs.readlink(path+'/phy80211')!=link)return null;
	return {ifindex,phyindex,phy};
}
function capture(deadline) {
	remaining(deadline);
	// Only UCI capture uses the short lock. netifd, sysfs and hostapd queries
	// must never keep a configuration transaction waiting on a driver.
	let wireless=locked(()=>{
		let c=cursor('/etc/config','/var/run/mesh-manager-uci','');
		if(!c.load('wireless'))die('backend_unavailable: Wireless configuration is unavailable');
		return uci_sections(c.get_all('wireless'));
	},5),connection,netifd;
	remaining(deadline);
	try {
		connection=connect(null,1);
		netifd=connection?.call('network.wireless','status',{});
	} catch(e) {}
	connection?.disconnect();
	remaining(deadline);
	if(type(netifd)!='object')die('backend_unavailable: Actual wireless mapping is unavailable');
	let snapshot={wireless,netifd,bindings:{},hostapd:{}};
	for(let target in radio_targets(snapshot).radios)for(let entry in target.interfaces) {
		remaining(deadline);
		let binding=kernel_binding(entry.ifname);
		if(binding)snapshot.bindings[entry.ifname]=binding;
	}
	return snapshot;
}
function hostapd(ifname,deadline) {
	remaining(deadline);let connection,status=null;
	try {
		connection=connect(null,1);
		status=connection?.call('hostapd.'+ifname,'get_status',{});
	} catch(e) {}
	connection?.disconnect();remaining(deadline);
	return type(status)=='object'?status:null;
}
function observation(deadline,phase) {
	return radio_observation(deadline,phase,{capture,hostapd});
}

export function radio_check(args) {
	return local_radios(args,{now:monotonic,time,boot,run,snapshot:observation,
		identity:()=>locked(()=>load('identity.json'),5)});
}
