// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal } from './model.uc';
import { job_token } from './rpc_jobs.uc';

// The helper bounds its library calls at two seconds from main(). The
// supervisor also covers fork/exec and reaping, so reserve 500 ms for those
// steps while retaining the absolute limit for the complete diagnostic.
const RADIO_LIMIT=8,INTERFACE_LIMIT=4,RESULT_LIMIT=65536,BUDGET_MS=20000,HELPER_MS=2500;
const FLAGS=['no_10mhz','no_20mhz','no_ht40+','no_ht40-','no_80mhz','no_160mhz','no_he','no_ir','indoor_only'];
const HELPER_ISSUES=['dfs_not_exposed','no_running_interface','country_unavailable','country_invalid',
	'reported_channel_unavailable','reported_channel_invalid','reported_frequency_unavailable','reported_frequency_invalid',
	'reported_channel_mismatch','reported_txpower_unavailable','reported_txpower_invalid','reported_txpower_zero_unverified',
	'offset_unavailable','offset_invalid','channels_unavailable','channels_empty','channels_invalid','channels_truncated',
	'power_unavailable','power_empty','power_invalid','power_truncated'];
const HELPER_FIELDS=['schema','status','radio','phy','representative_interface','reported','channels','power','issues','dfs_complete','dfs_source'];
function number(value,minimum,maximum) { return type(value)=='int' && value>=minimum && value<=maximum; }
function nullable_number(value,minimum,maximum) { return value===null || number(value,minimum,maximum); }
function name(value,maximum) {
	if(type(value)!='string' || !length(value) || length(value)>maximum)return false;
	for(let n=0;n<length(value);n++)if(index('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-',substr(value,n,1))<0)return false;
	return true;
}
function country(value) {
	if(value==='00')return true;
	return type(value)=='string' && length(value)==2 &&
		index('ABCDEFGHIJKLMNOPQRSTUVWXYZ',substr(value,0,1))>=0 && index('ABCDEFGHIJKLMNOPQRSTUVWXYZ',substr(value,1,1))>=0;
}
function fields(value,allowed) {
	return type(value)=='object' && length(keys(value))==length(allowed) &&
		!length(filter(keys(value),key=>index(allowed,key)<0));
}
function add(issues,issue) { if(index(issues,issue)<0)push(issues,issue); }
function status(complete,reliable) { return complete?'complete':reliable?'partial':'unavailable'; }
function empty_axis(kind) {
	return kind=='channels'?{status:'unavailable',complete:false,truncated:false,items:[]}:
		{status:'unavailable',complete:false,truncated:false,scope:'operating_channel_unknown',channel:null,raw_dbm:[],offset_db:null};
}
function configured(section) {
	let values=section?.values || {},channel=values.channel,txpower=values.txpower;
	function decimal(value,max) {
		if(type(value)=='int')return number(value,0,max)?value:null;
		if(type(value)!='string' || !length(value) || length(value)>3)return null;
		for(let n=0;n<length(value);n++)if(index('0123456789',substr(value,n,1))<0)return null;
		return ''+int(value)==value && int(value)<=max?int(value):null;
	}
	let selected=decimal(channel,233);
	return {band:index(['2g','5g','6g','60g'],values.band)>=0?values.band:null,
		channel:channel==='auto'?'auto':selected!==null && selected>0?selected:null,country:country(values.country)?values.country:null,
		txpower:decimal(txpower,63)};
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
function channels(value,issues) {
	let result=empty_axis('channels');
	if(!fields(value,['status','complete','truncated','items']) || index(['complete','partial','unavailable'],value.status)<0 ||
		type(value.complete)!='bool' || type(value.truncated)!='bool' || type(value.items)!='array') { add(issues,'channels_invalid');return result; }
	if(value.status=='unavailable') { add(issues,'channels_unavailable');return result; }
	let invalid=false,seen={};result.truncated=value.truncated || length(value.items)>256;
	for(let item in slice(value.items,0,256)) {
		let band=item?.band,freq=item?.frequency_mhz,
			valid=fields(item,['band','channel','frequency_mhz','restricted','flags','dfs_required']) &&
				type(band)=='int' && index([2,5,6,60],band)>=0 && number(item.channel,1,233) && number(freq,1000,71000) &&
				type(item.restricted)=='bool' && type(item.flags)=='array' && length(item.flags)<=9 &&
				length(uniq(item.flags))==length(item.flags) && !length(filter(item.flags,flag=>type(flag)!='string' || index(FLAGS,flag)<0)) &&
				item.dfs_required===null &&
				(band==2 && freq>=2300 && freq<=2500 || band==5 && freq>=4900 && freq<5925 ||
				 band==6 && freq>=5925 && freq<=7125 || band==60 && freq>=57000 && freq<=71000);
		let key=''+band+'/'+freq;
		if(!valid || seen[key]) { invalid=true;continue; }
		seen[key]=true;push(result.items,{band,channel:item.channel,frequency_mhz:freq,restricted:item.restricted,
			flags:clone(item.flags),dfs_required:null,dfs_source:'not_exposed_by_backend'});
	}
	if(invalid)add(issues,'channels_invalid');
	if(result.truncated)add(issues,'channels_truncated');
	if(!length(result.items))add(issues,'channels_empty');
	result.complete=value.status=='complete' && value.complete && !invalid && !result.truncated && length(result.items)>0;
	result.status=status(result.complete,length(result.items)>0);return result;
}
function power(value,issues) {
	let result=empty_axis('power');
	if(!fields(value,['status','complete','truncated','scope','channel','raw_dbm','offset_db']) ||
		index(['complete','partial','unavailable'],value.status)<0 || type(value.complete)!='bool' || type(value.truncated)!='bool' ||
		type(value.raw_dbm)!='array') { add(issues,'power_invalid');return result; }
	if(value.status=='unavailable') { add(issues,'power_unavailable');return result; }
	let invalid=false;result.truncated=value.truncated || length(value.raw_dbm)>64;
	for(let dbm in slice(value.raw_dbm,0,64)) {
		if(!number(dbm,0,63) || index(result.raw_dbm,dbm)>=0) { invalid=true;continue; }
		push(result.raw_dbm,dbm);
	}
	result.offset_db=nullable_number(value.offset_db,-32,32)?value.offset_db:null;
	// v1 libiwinfo txpwrlist independently resamples/falls back by channel
	// number. It cannot prove the list belongs to the reported operating band.
	if(value.scope!='operating_channel_unknown' || value.channel!==null || result.offset_db!==value.offset_db)invalid=true;
	if(invalid)add(issues,'power_invalid');
	if(result.truncated)add(issues,'power_truncated');
	if(!length(result.raw_dbm))add(issues,'power_empty');
	result.complete=value.status=='complete' && value.complete && !invalid && !result.truncated && length(result.raw_dbm)>0;
	result.status=status(result.complete,length(result.raw_dbm)>0);return result;
}
function empty_reported() {
	return {channel:null,frequency_mhz:null,country:null,txpower_dbm:null,txpower_offset_db:null,
		actual_txpower_dbm:null,source:'libiwinfo',txpower_source:'unavailable'};
}
function helper(result,radio,ifname) {
	let unavailable={phy:null,reported:empty_reported(),channels:empty_axis('channels'),power:empty_axis('power'),
		issues:['helper_unavailable'],complete:false};
	if(result?.code==-2)die('request_timeout: Radio helper exceeded its deadline');
	if(index([0,1],result?.code)<0 || type(result.stdout)!='string' || !length(result.stdout) || length(result.stdout)>RESULT_LIMIT)return unavailable;
	let value;try { value=json(result.stdout); } catch(e) { return unavailable; }
	if(type(value)!='object' || type(value.schema)!='int' || value.schema!=1)return unavailable;
	if(result.code==1) {
		if(!fields(value,['schema','status','reason']) || value.status!='unavailable' ||
			index(['invalid_request','backend_unavailable','phy_unavailable','interface_unavailable','target_changed','budget_exceeded','read_failed','result_too_large'],value.reason)<0)return unavailable;
		if(value.reason=='target_changed')die('target_changed: Radio or interface mapping changed during the query');
		if(value.reason=='budget_exceeded')die('request_timeout: Radio helper exceeded its deadline');
		unavailable.issues=['helper_'+value.reason];return unavailable;
	}
	let reported=value.reported;
	if(type(value)!='object' || length(filter(keys(value),field=>index(HELPER_FIELDS,field)<0)) ||
		value.radio!=radio || value.representative_interface!==ifname || !name(value.phy,64) ||
		index(['complete','partial','unavailable'],value.status)<0 || value.dfs_complete!==false || value.dfs_source!='not_exposed_by_backend' ||
		type(value.issues)!='array' || length(value.issues)>length(HELPER_ISSUES) || length(uniq(value.issues))!=length(value.issues) ||
		length(filter(value.issues,issue=>type(issue)!='string' || index(HELPER_ISSUES,issue)<0)))return unavailable;
	let reported_valid=fields(reported,['channel','frequency_mhz','country','txpower_dbm','txpower_offset_db','actual_txpower_dbm','source','txpower_source']) &&
		nullable_number(reported.channel,1,233) && nullable_number(reported.frequency_mhz,1000,71000) &&
		(reported.country===null || country(reported.country)) && nullable_number(reported.txpower_dbm,0,63) &&
		nullable_number(reported.txpower_offset_db,-32,32) && reported.actual_txpower_dbm===null && reported.source=='libiwinfo' &&
		index(['backend_reported','zero_unverified','unavailable'],reported.txpower_source)>=0 &&
		!(reported.txpower_source=='unavailable' && reported.txpower_dbm!==null ||
		  reported.txpower_source=='zero_unverified' && reported.txpower_dbm!==0 ||
		  reported.txpower_source=='backend_reported' && !number(reported.txpower_dbm,1,63) ||
		  ifname===null && (reported.channel!==null || reported.frequency_mhz!==null || reported.txpower_dbm!==null));
	let issues=clone(value.issues),channel_axis=channels(value.channels,issues),power_axis=power(value.power,issues);
	if(!reported_valid) { reported=empty_reported();add(issues,'reported_invalid'); }
	if(reported_valid && reported.txpower_offset_db!==power_axis.offset_db && power_axis.status!='unavailable') {
		power_axis.offset_db=null;power_axis.complete=false;power_axis.status=status(false,length(power_axis.raw_dbm)>0);add(issues,'offset_mismatch');
	}
	let reference_complete=reported.country!==null && reported.txpower_offset_db!==null &&
		(ifname===null || reported.channel!==null && reported.frequency_mhz!==null && reported.txpower_source=='backend_reported');
	return {phy:value.phy,reported:clone(reported),channels:channel_axis,power:power_axis,issues,
		complete:value.status=='complete' && reported_valid && reference_complete && channel_axis.complete && power_axis.complete &&
			!length(filter(issues,issue=>index(['dfs_not_exposed','no_running_interface'],issue)<0))};
}
function hostapd_interface(iface,snapshot,phy,physical_index) {
	let observed=snapshot.hostapd?.[iface.ifname],binding=snapshot.bindings?.[iface.ifname],running=null,cac=null,
		available=number(binding?.ifindex,1,2147483647) && number(binding?.phyindex,0,2147483647) &&
			name(binding?.phy,64) && binding.phy===phy && physical_index!==null && binding.phyindex===physical_index;
	if(name(phy,64) && type(observed)=='object' && observed.phy===phy &&
		available &&
		index(['UNINITIALIZED','DISABLED','COUNTRY_UPDATE','ACS','HT_SCAN','DFS','ENABLED'],observed.status)>=0) {
		if(number(observed.channel,1,233) && number(observed.freq,1000,71000))
			running={state:observed.status,channel:observed.channel,frequency_mhz:observed.freq,source:'hostapd'};
		if(type(observed.dfs?.cac_active)=='bool' && number(observed.dfs?.cac_seconds_left,0,3600))
			cac={active:observed.dfs.cac_active,seconds_left:observed.dfs.cac_seconds_left,source:'hostapd'};
	}
	return {section:iface.section,ifname:iface.ifname,mode:iface.mode,
		available,running,cac};
}
function raw(snapshot) { return {wireless:snapshot?.wireless,netifd:snapshot?.netifd,bindings:snapshot?.bindings}; }

// The final raw capture closes the window opened by slow hostapd queries:
// rebuilding a same-name netdev or changing even a redacted password must not
// let observations from another configuration masquerade as this snapshot.
export function radio_observation(deadline,phase,io) {
	if((type(deadline)!='int' && type(deadline)!='double') || !(deadline>0 && deadline<9007199254740991) ||
		index(['before','after'],phase)<0)die('invalid_request: Invalid radio observation phase or deadline');
	let initial=clone(io.capture(deadline));
	if(phase=='before')return initial;
	let observed={};
	for(let plan in radio_targets(initial).radios)for(let iface in plan.interfaces) {
		let binding=initial.bindings?.[iface.ifname];
		if(iface.mode!='ap' || !number(binding?.ifindex,1,2147483647) ||
			!number(binding?.phyindex,0,2147483647) || !name(binding?.phy,64))continue;
		let value=io.hostapd(iface.ifname,deadline);
		if(type(value)=='object')observed[iface.ifname]=clone(value);
	}
	let final=clone(io.capture(deadline));
	if(!equal(raw(initial),raw(final)))die('target_changed: Original radio configuration or interface mapping changed during hostapd observation');
	initial.hostapd=observed;
	return initial;
}
export function local_radios(args,io) {
	if(type(args)!='object' || length(keys(args))!=2 || args.check!='local_radios' || !job_token(args.node_id))
		die('invalid_request: Invalid local radio diagnostic arguments');
	let start=io.now();
	if(type(start)!='int' && type(start)!='double' || !(start>=0 && start<9007199254720991))die('request_timeout: Monotonic clock is unavailable');
	let deadline=start+BUDGET_MS,identity=clone(io.identity()),initial_boot=io.boot();
	if(identity?.id!=args.node_id || !job_token(identity?.id) || type(initial_boot)!='string' || !length(initial_boot))
		die('target_unavailable: Local radio identity is unavailable');
	function budget(required) { let now=io.now();if(type(now)!='int' && type(now)!='double' || !(now>=start && now<deadline) || deadline-now<required)die('request_timeout: Local radio diagnostics exceeded their deadline'); }
	budget(HELPER_MS);let before=io.snapshot(deadline,'before'),captured=clone(raw(before)),targets=radio_targets(before),rows=[];
	for(let plan in targets.radios) {
		budget(HELPER_MS);let available=filter(plan.interfaces,iface=>number(before.bindings?.[iface.ifname]?.ifindex,1,2147483647) &&
			number(before.bindings?.[iface.ifname]?.phyindex,0,2147483647) && name(before.bindings?.[iface.ifname]?.phy,64)),representative=available[0]?.ifname || null,
			value=name(plan.radio,64)?helper(io.run(['/usr/libexec/mesh-manager-radio-info',plan.radio,...(representative?[representative]:[])],'',HELPER_MS),plan.radio,representative):
				{phy:null,reported:empty_reported(),channels:empty_axis('channels'),power:empty_axis('power'),issues:['invalid_radio_name'],complete:false};
		budget(0);push(rows,{radio:name(plan.radio,64)?plan.radio:null,phy:value.phy,representative_interface:representative,
			configured:configured(before.wireless[plan.radio]),...value,interfaces:[],interfaces_complete:plan.interfaces_complete,
			running:null,cac:null,dfs_complete:false,dfs_source:'not_exposed_by_backend'});
	}
	budget(0);let after=io.snapshot(deadline,'after');budget(0);
	if(!equal(captured,raw(after)) || !equal(identity,io.identity()) || initial_boot!=io.boot())
		die('target_changed: Device identity or original radio configuration and mapping changed during the query');
	for(let n=0;n<length(rows);n++) {
		let row=rows[n],plan=targets.radios[n],reference=after.bindings?.[row.representative_interface],
			physical_index=reference?.phy===row.phy && number(reference?.phyindex,0,2147483647)?reference.phyindex:null;
		row.interfaces=map(plan.interfaces,iface=>hostapd_interface(iface,after,row.phy,physical_index));
		if(!plan.interfaces_complete || length(filter(row.interfaces,iface=>!iface.available))) {
			row.complete=false;row.interfaces_complete=false;add(row.issues,plan.interfaces_truncated?'interfaces_truncated':'mapping_unavailable');
		}
		if(length(filter(row.interfaces,iface=>iface.mode=='ap' && (!iface.running || !iface.cac)))) {
			row.complete=false;add(row.issues,'interfaces_runtime_incomplete');
		}
		let shared=row.phy!==null && length(filter(rows,other=>other.phy==row.phy))>1,
			observed=filter(row.interfaces,iface=>iface.running),representative=filter(row.interfaces,iface=>iface.ifname==row.representative_interface)[0],
			ambiguous=shared || length(uniq(map(observed,iface=>''+iface.running.channel+'/'+iface.running.frequency_mhz)))>1;
		if(ambiguous) {
			row.complete=false;add(row.issues,shared?'shared_phy_mapping':'ambiguous_running_channel');
			row.reported.channel=null;row.reported.frequency_mhz=null;row.reported.txpower_dbm=null;row.reported.txpower_source='unavailable';
			row.power.scope='operating_channel_unknown';row.power.channel=null;row.power.complete=false;
			row.power.status=status(false,length(row.power.raw_dbm)>0);
		} else {
			row.running=representative?.running || null;row.cac=representative?.cac || null;
			if(row.representative_interface && (!row.running || !row.cac)) { row.complete=false;add(row.issues,'running_unavailable'); }
			if(row.running && (row.reported.channel!==null && row.reported.channel!=row.running.channel ||
				row.reported.frequency_mhz!==null && row.reported.frequency_mhz!=row.running.frequency_mhz)) {
				row.complete=false;add(row.issues,'running_channel_mismatch');row.power.complete=false;
				row.power.scope='operating_channel_unknown';row.power.channel=null;row.power.status=status(false,length(row.power.raw_dbm)>0);
			}
		}
		row.status=status(row.complete,length(row.channels.items)>0 || length(row.power.raw_dbm)>0);
	}
	let reliable=length(filter(rows,row=>row.status!='unavailable'))>0,
		complete=!targets.truncated && length(rows)>0 && !length(filter(rows,row=>!row.complete)),
		result={schema:1,scope:'local_radios',node_id:identity.id,observed_at:io.time(),observed_uptime_ms:io.now(),
			status:status(complete,reliable),complete,radio_total:targets.radio_total,radio_limit:RADIO_LIMIT,truncated:targets.truncated,radios:rows};
	budget(0);
	if(length(sprintf('%J',result))>RESULT_LIMIT)die('result_too_large: Local radio diagnostics exceed their result limit');
	return result;
}
