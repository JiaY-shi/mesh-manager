// SPDX-License-Identifier: GPL-2.0-only
'use strict';
export const RADIO_LIMIT=8,INTERFACE_LIMIT=4;
function name(value,maximum) {
 if(type(value)!='string' || !length(value) || length(value)>maximum)return false;
 for(let n=0;n<length(value);n++)if(index('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-',substr(value,n,1))<0)return false;
 return true;
}

// This same bounded selection lets the service capture real kernel bindings
// and hostapd status without guessing radio0 == phy0 or selecting by UI input.
export function radio_targets(snapshot) {
	if(type(snapshot?.wireless)!='object')die('backend_unavailable: Wireless configuration is unavailable');
	let wireless=snapshot.wireless,radios=sort(filter(keys(wireless),key=>wireless[key]?.type=='wifi-device')),plans=[];
	for(let radio in slice(radios,0,RADIO_LIMIT)) {
		let runtime=snapshot.netifd?.[radio],raw=runtime?.interfaces,interfaces=[],complete=type(runtime)=='object' && type(raw)=='array';
		for(let iface in type(raw)=='array'?raw:[]) {
			let section=iface?.section,ifname=iface?.ifname,options=wireless[section]?.values,mode=options?.mode;
			if(!name(section,64) || !name(ifname,15) || wireless[section]?.type!='wifi-iface' || options?.device!=radio ||
				index(['ap','sta','mesh','adhoc','monitor','wds'],mode)<0 ||
				length(filter(interfaces,row=>row.section==section || row.ifname==ifname))) { complete=false;continue; }
			push(interfaces,{section,ifname,mode});
		}
		sort(interfaces,(a,b)=>{
			let ranka=a.section=='mm_ap_'+radio && a.mode=='ap'?0:a.mode=='ap'?1:2,
				rankb=b.section=='mm_ap_'+radio && b.mode=='ap'?0:b.mode=='ap'?1:2;
			return ranka!=rankb?ranka-rankb:a.section!=b.section?a.section<b.section?-1:1:a.ifname<b.ifname?-1:a.ifname>b.ifname?1:0;
		});
		let truncated=length(interfaces)>INTERFACE_LIMIT;
		push(plans,{radio,interfaces:slice(interfaces,0,INTERFACE_LIMIT),interfaces_complete:complete && !truncated,
			interfaces_truncated:truncated});
	}
	return {radio_total:length(radios),truncated:length(radios)>RADIO_LIMIT,radios:plans};
}
