// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import { run } from 'mesh_process';
import { equal } from './model.uc';
import { radio_targets } from './radio_mapping.uc';
import { planning_radios, running_power, running_channel, channel_matches } from './radio_planning.uc';
import { regulatory_binding } from './regulatory_worker.uc';

// Readback shares the existing runtime graph; loading full diagnostic/planning
// workers here would retain a second graph in the long-lived AP agent.
export function frozen_power_health(intent,snapshot,io) {
	if ((!intent.wifi?.enabled && !length(filter(intent.networks || [], n=>n.enabled))) ||
		!intent.wifi?.planning?.enabled || intent.wifi.planning.power!='auto' && intent.wifi.planning.channel!='auto')return [];
	let names=planning_radios(intent,{radios:map(filter(keys(snapshot.wireless),n=>snapshot.wireless[n].type=='wifi-device'),
		n=>({name:n,band:snapshot.wireless[n].values.band}))}),checks=[],
		plans=radio_targets({wireless:snapshot.wireless,netifd:io.netifd()}).radios;
	for (let radio in names) {
		let config=snapshot.wireless[radio].values,configured=config.txpower,limit=match(configured || '',/^(0|[1-9][0-9]?)$/) ? int(configured)*100 : null,
			plan=filter(plans,p=>p.radio==radio)[0],interfaces=filter(plan?.interfaces || [],i=>match(i.section || '',/^mm_/));
		let complete=length(interfaces)>0 && plan?.interfaces_complete===true,
			ok=complete && limit!=null && limit<=intent.wifi.planning.max_txpower_dbm*100,
			channel_ok=complete,readings=[],channels=[],shared=intent.backhaul?.mode!='wired' && intent.local?.mesh_radio==radio;
		for (let iface in interfaces) {
			let before=io.binding(iface.ifname),readback=before ? io.run(['/usr/sbin/iw','dev',iface.ifname,'info'],'',1000) : null,
				power=readback?.code===0 ? running_power(readback.stdout,iface.ifname,before.phyindex) : null,
				channel=readback?.code===0 ? running_channel(readback.stdout,iface.ifname,before.phyindex) : null,
				after=io.binding(iface.ifname);
			if (!before || !equal(before,after) || power==null || power>limit)ok=false;
			if (!before || !equal(before,after) || !channel_matches(config,channel,shared))channel_ok=false;
			push(readings,{interface:iface.ifname,driver_mbm:power});
			push(channels,{interface:iface.ifname,...(channel || {})});
		}
		if (intent.wifi.planning.power=='auto')push(checks,{name:'power_ceiling_'+radio,ok,limit_mbm:limit,readings});
		push(checks,{name:'channel_'+radio,ok:channel_ok,readings:channels});
	}
	return checks;
}
export function planning_power_health(intent,snapshot,bus) {
	return frozen_power_health(intent,snapshot,{
		netifd:()=>{try{return bus?.call('network.wireless','status',{});}catch(e){return null;}},
		binding:ifname=>regulatory_binding(ifname,{read:fs.readfile,stat:fs.stat,readlink:fs.readlink}),run
	});
}
