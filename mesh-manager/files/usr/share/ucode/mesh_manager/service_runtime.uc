// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import * as ubus from 'ubus';
import { run } from 'mesh_process';
import { sha256 } from 'mesh_crypto';
import { load,read,boot,now } from './durable.uc';
import { service_policy } from './service_policy.uc';

const DEMAND='/var/run/mesh-manager-demand.json';
export function service_desired() {
	let demand=false,st=fs.lstat(DEMAND);
	if(st?.type=='file' && st.uid==0 && !(st.mode & 0077) && st.size<=256) {
		try {let d=json(fs.readfile(DEMAND)),clock=now();demand=d.boot==boot() &&
			d.created<=clock && d.expires==d.created+60 && clock<d.expires &&
			d.identity==sha256(read('identity.json') || 'absent');}catch(e){}
	}
	let identity,state,cluster;
	try{identity=load('identity.json');state=load('state.json');if(identity?.role=='root')cluster=load('cluster.json');}
	catch(e){return service_policy({schema:-1},null,true,demand);}
	let result = service_policy(identity,state,
		fs.lstat('/var/run/mesh-manager-onboard')!=null || fs.lstat('/sys/class/net/mm-onboard')!=null,demand,cluster);
	result.listeners={};
	for(let name in ['node','enroll','control']) {
		if(index(result.instances,name)<0)continue;
		let address=name=='control' ? identity?.role=='root' ? identity.control_address || '169.254.254.1' :
			identity?.anchor!=null && identity.id!=null && identity.anchor.id==identity.id ? '169.254.254.1' :
			identity?.migration!=null && identity.id!=null && identity.migration.target==identity.id ? identity.migration.binding?.control_address : identity.control_address :
			identity?.role=='root' ? identity.address : identity.anchor?.address;
		result.listeners[name]={address,port:name=='enroll'?37902:37901,mode:name=='enroll'?'enroll':'node'};
	}

	return result;
}
export function wake_service() {
	if(!fs.access('/etc/init.d/mesh-manager'))return;
	let f=fs.open(DEMAND,'w',0600),created=now(),text=sprintf('%J',{boot:boot(),created,expires:created+60,
		identity:sha256(read('identity.json') || 'absent')});
	if(f?.write(text)!=length(text) || !f?.close())die('service_error: Cannot request the recovery service');
	if(run(['/etc/init.d/mesh-manager','reload'],'',5000)?.code!==0)
		die('service_error: Cannot start the recovery service');
	let b=ubus.connect(),instance;
	try{instance=b?.call('service','list',{name:'mesh-manager'})?.['mesh-manager']?.instances?.instance1;}catch(e){}
	b?.disconnect();
	let already_running=instance?.running===true && type(instance.pid)=='int' && instance.pid>1 &&
		fs.lstat('/proc/'+instance.pid)!=null && type(instance.command)=='array' &&
		(length(instance.command)==1 && instance.command[0]=='/usr/sbin/mesh-manager' ||
			length(instance.command)==2 && instance.command[0]=='/usr/bin/ucode' &&
			instance.command[1]=='/usr/sbin/mesh-manager');
	// No configuration can be staged until the actual recovery heartbeat exists.
	// A cold procd instance may still be in its five-second respawn interval.
	// Keep this startup budget separate from transaction confirmation health.
	for(let attempt=0;attempt<100;attempt++) {
		let heartbeat;try{heartbeat=json(fs.readfile('/var/run/mesh-manager.heartbeat') || 'null');}catch(e){}
		let clock=now();if(heartbeat?.boot==boot() && (heartbeat.uptime>=created || already_running) &&
			heartbeat.uptime<=clock && clock-heartbeat.uptime<10)return;
		sleep(100);
	}
	die('daemon_unavailable: Recovery service did not become ready');
}
let next=0;
export function reconcile_services() {
	let clock=now();if(clock<next)return;next=clock+5;
	let desired=service_desired(),b=ubus.connect(),actual;
	try{actual=b?.call('service','list',{name:'mesh-manager'})?.['mesh-manager']?.instances;}catch(e){}
	b?.disconnect();
	if(type(actual)!='object')return;
	let names=keys(actual);
	if(length(names)==length(desired.instances) && !length(filter(names,n=>
		index(desired.instances,n)<0 || actual[n].running!==true)) &&
		!length(filter(keys(desired.listeners),name=>join(' ',actual[name]?.command || [])!=join(' ',[
			'/usr/libexec/mesh-manager-channel','serve',desired.listeners[name].address,''+desired.listeners[name].port,
			'/etc/mesh-manager/network-ca.crt','/etc/mesh-manager/device.crt','/etc/mesh-manager/device.key',desired.listeners[name].mode]))))return;
	if(run(['/etc/init.d/mesh-manager','reload'],'',5000)?.code!==0)
		die('service_error: Cannot reconcile Mesh background services');
}
