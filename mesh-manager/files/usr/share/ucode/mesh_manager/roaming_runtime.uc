// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import { equal } from './model.uc';
import { steering_options, steering_health, steering_policy } from './roaming.uc';

let installation;
function installed() {
	let paths=['/sbin/usteerd','/etc/init.d/usteer','/lib/apk/db/installed','/usr/lib/opkg/info/usteer.control'],
		signature=map(paths,path=>{let st=fs.stat(path);return st?[st.inode,st.size,st.mtime,st.ctime]:null;});
	if (installation && equal(installation.signature,signature)) return installation.value;
	let script=signature[1]?.[1]<=32768 ? fs.readfile(paths[1]) || '' : '', words={}, word='';
	for(let ch in split(script,'')) {
		if (index('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789',ch)>=0) word+=ch;
		else if(word) { words[word]=true;word=''; }
	}
	if(word)words[word]=true;
	let version=null, packages=fs.stat(paths[2])?.size<=2*1024*1024 ? fs.readfile(paths[2]) : null;
	if(packages) {
		let start=index('\n'+packages,'\nP:usteer\n');
		if(start>=0)for(let line in split(split(substr('\n'+packages,start+1),'\n\n')[0],'\n'))
			if(index(line,'V:')==0)version=substr(line,2);
	} else {
		let control=fs.stat(paths[3])?.size<=32768 ? fs.readfile(paths[3]) : null;
		for(let line in split(control || '','\n'))if(index(line,'Version: ')==0)version=substr(line,9);
	}
	let value={installed:signature[0]!=null && signature[1]!=null,version,
		conflicting_backend:packages ? index('\n'+packages,'\nP:usteer-ng\n')>=0 : fs.stat('/usr/lib/opkg/info/usteer-ng.control')!=null,
		words};
	installation={signature,value};return value;
}
function call(b,object,method,args) {
	try { b?.error();let result=b?.call(object,method,args || {});return b && b.error()==null ? result : null; }
	catch(e) { return null; }
}
function sample(b) {
	let services=call(b,'service','list',{name:'usteer'}),running=null,methods=null,config=null;
	if(type(services)=='object')running=length(filter(values(services.usteer?.instances || {}),instance=>instance.running===true))>0;
	if(running) {
		try { methods=b.list('usteer')?.[0] || null; } catch(e) {}
		config=call(b,'usteer','get_config',{});
	}
	return {running,methods,config};
}
function support(live) {
	let data=installed(), options=keys(steering_options({controller:true,wifi:{enabled:true,ssid:'',roaming:{steering:true}}})),
		missing=filter(options,option=>!data.words[option] || live.methods &&
			index(['enabled','network'],option)<0 && live.methods.set_config?.[option]==null);
	let boot_enabled=length(fs.glob('/etc/rc.d/S??usteer') || [])>0;
	return {installed:data.installed,version:data.version,running:live.running,boot_enabled,
		conflicting_backend:data.conflicting_backend,supported:data.installed && !length(missing),missing};
}
export function steering_capabilities(b) { return support(sample(b)); }

function network_devices(snapshot, networks) {
	if (type(networks)=='string')networks=filter(split(networks,' '),name=>length(name));
	if (type(networks)!='array' || !length(networks))return null;
	let devices=map(networks,name=>snapshot.network?.[name]?.values?.device);
	return length(filter(devices,name=>type(name)!='string' || !length(name))) ? null : devices;
}
export function steering_observation(snapshot,intent,managed,b) {
	let live=sample(b),cap=support(live),enabled=intent?.wifi?.roaming?.steering===true,
		options=managed && intent?.schema==2 ? steering_options(intent) : null,
		checks=options ? steering_health(options,live.running,live.config,network_devices(snapshot,options.network)) : [];
	return {...cap,managed,requested:enabled,healthy:managed ? !length(filter(checks,c=>!c.ok)) : null,
		checks,interfaces:type(live.config?.interfaces)=='array' ? slice(filter(live.config.interfaces,
			name=>type(name)=='string' && length(name)<=15),0,8) : [],
		policy:managed && enabled ? 'advisory' : null,
		thresholds:managed ? steering_policy(intent.wifi.roaming) : null};
}
export function steering_verify(snapshot,active,b) {
	let changed=filter(active.ops || [],op=>op.config=='usteer');
	if(!length(changed))return [];
	let live=sample(b);
	if(active.intent?.schema==2) {
		let options=steering_options(active.intent);
		return steering_health(options,live.running,live.config,network_devices(snapshot,options.network));
	}
	// Release restores the original service. Verify its start/stop state and its
	// original communication interfaces; transaction health also checks every UCI value.
	let sections=filter(values(snapshot.usteer || {}),section=>section.type=='usteer');
	if(length(sections)!=1)return [{name:'usteer_restored_configuration',ok:false}];
	let original=sections[0].values,enabled=original.enabled ?? '1';
	if(enabled=='0')return [{name:'usteer_stopped',ok:live.running===false}];
	let restored={enabled:'1',network:original.network};
	for (let op in changed) if (op.option && op.option!='enabled' && original[op.option]!=null)
		restored[op.option]=original[op.option];
	return steering_health(restored,live.running,live.config,
		network_devices(snapshot,original.network));
}
