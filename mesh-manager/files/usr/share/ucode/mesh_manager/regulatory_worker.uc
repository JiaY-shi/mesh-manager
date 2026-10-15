// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal } from './model.uc';

export const REGULATORY_FLAGS=['disabled','no_ir','no_ibss','radar','no_ht40_minus','no_ht40_plus',
	'no_10mhz','no_20mhz','no_80mhz','no_160mhz','no_320mhz','no_he','no_eht','indoor_only','ir_concurrent',
	'1mhz','2mhz','4mhz','8mhz','16mhz'];
export const REGULATORY_ISSUES=['no_running_interface','mapping_unavailable','interfaces_incomplete','interfaces_truncated',
	'configured_country_invalid','regulatory_unavailable','regulatory_invalid','global_regulatory_unavailable','global_regulatory_invalid',
	'frequencies_unavailable','frequencies_invalid','frequencies_empty','frequencies_truncated','frequency_fields_unknown',
	'frequency_power_unavailable','frequency_power_invalid','frequency_dfs_unknown','frequency_dfs_invalid','frequency_offset_invalid',
	'frequency_psd_invalid','unsupported_band','current_unavailable','current_incomplete','current_invalid','current_changed',
	'interfaces_current_incomplete','ambiguous_current','mlo_unsupported','shared_phy_mapping','result_truncated',
	'helper_unavailable','helper_invalid_request','helper_backend_unavailable','helper_read_failed','helper_result_too_large'];
export function regulatory_number(value,min,max) { return type(value)=='int' && value>=min && value<=max; }
export function regulatory_name(value,max) {
	if(type(value)!='string' || !length(value) || length(value)>max || index(['.','-'],substr(value,0,1))>=0)return false;
	for(let n=0;n<length(value);n++)if(index('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-',substr(value,n,1))<0)return false;
	return true;
}
export function regulatory_country(value) {
	if(index(['00','98','99'],value)>=0)return true;
	return type(value)=='string' && length(value)==2 && index('ABCDEFGHIJKLMNOPQRSTUVWXYZ',substr(value,0,1))>=0 &&
		index('ABCDEFGHIJKLMNOPQRSTUVWXYZ',substr(value,1,1))>=0;
}
export function regulatory_fields(value,fields) {
	return type(value)=='object' && length(keys(value))==length(fields) && !length(filter(keys(value),k=>index(fields,k)<0));
}
export function regulatory_add(issues,code) { if(index(issues,code)<0)push(issues,code); }
export function regulatory_status(complete,reliable) { return complete?'complete':reliable?'partial':'unavailable'; }
export function regulatory_empty_current() {
	return {status:'unavailable',source:'driver_reported',interface:null,frequency_mhz:null,channel_width:null,
		center_freq1_mhz:null,center_freq2_mhz:null,txpower_mbm:null,mlo:false};
}
export function regulatory_empty(radio,phy,country) {
	return {radio,phy,status:'unavailable',complete:false,
		regulatory:{status:'unavailable',configured_country:regulatory_country(country)?country:null,alpha2:null,
			scope:'unavailable',global_alpha2:null,country_match:null,self_managed:null},
		current:regulatory_empty_current(),frequencies:{status:'unavailable',truncated:false,items:[]},issues:[]};
}
function directory(value) {
	return regulatory_fields(value,['dev','inode']) && regulatory_fields(value.dev,['major','minor']) &&
		regulatory_number(value.dev.major,0,4294967295) && regulatory_number(value.dev.minor,0,4294967295) &&
		regulatory_number(value.inode,1,9007199254740991);
}
export function regulatory_valid_binding(value) {
	return regulatory_fields(value,['ifindex','phyindex','phy','interface_directory','phy_directory','up']) &&
		regulatory_number(value.ifindex,1,2147483647) && regulatory_number(value.phyindex,0,2147483647) &&
		regulatory_name(value.phy,63) && directory(value.interface_directory) && directory(value.phy_directory) && value.up===true;
}
export function regulatory_valid_phy_binding(value) {
	return regulatory_fields(value,['phy','phyindex','phy_directory']) && regulatory_name(value.phy,63) &&
		regulatory_number(value.phyindex,0,2147483647) && directory(value.phy_directory);
}
export function regulatory_phy_binding(phy,io) {
	if (!regulatory_name(phy,63)) return null;
	let path='/sys/class/ieee80211/'+phy;
	function capture() {
		let dir=io.stat(path),text=io.read(path+'/index'),raw=type(text)=='string' ? trim(text) : '';
		if (dir?.type!='directory' || type(text)!='string' || length(text)>11 ||
			(text!=raw && text!=raw+'\n') || index(raw,'\n')>=0 || index(raw,'\r')>=0 || index(raw,'\0')>=0 ||
			!match(raw,/^(0|[1-9][0-9]{0,9})$/)) return null;
		let value={phy,phyindex:int(raw),phy_directory:{dev:clone(dir.dev),inode:dir.inode}};
		return regulatory_valid_phy_binding(value) ? value : null;
	}
	let before=capture(),after=capture();
	return before && equal(before,after) ? before : null;
}
// Shared by the service and the short-lived worker. Follow actual sysfs links;
// a renamed PHY never gets an index inferred from its name.
export function regulatory_binding(ifname,io) {
	if(!regulatory_name(ifname,15))return null;
	let path='/sys/class/net/'+ifname;
	function decimal(file) {
		let text=trim(io.read(file) || '');
		if(!length(text) || length(text)>10)return null;
		for(let n=0;n<length(text);n++)if(index('0123456789',substr(text,n,1))<0)return null;
		let value=int(text);return regulatory_number(value,0,2147483647) && ''+value==text?value:null;
	}
	function capture() {
		let link=io.readlink(path+'/phy80211'),parts=type(link)=='string'?split(link,'/'):[],phy=parts[length(parts)-1],
			iface=io.stat(path),physical=io.stat(path+'/phy80211'),flags=trim(io.read(path+'/flags') || '');
		if(iface?.type!='directory' || physical?.type!='directory' || !match(flags,/^0x[0-9a-fA-F]{1,8}$/))return null;
		let binding={ifindex:decimal(path+'/ifindex'),phyindex:decimal(path+'/phy80211/index'),phy,
			interface_directory:{dev:clone(iface?.dev ?? null),inode:iface?.inode ?? null},
			phy_directory:{dev:clone(physical?.dev ?? null),inode:physical?.inode ?? null},up:!!(int(substr(flags,2),16)&1)};
		return regulatory_valid_binding(binding)?binding:null;
	}
	try { let first=capture(),second=capture();return first && equal(first,second)?first:null; }catch(e){return null;}
}
export function regulatory_signed_mbm(value) {
	if(!regulatory_number(value,0,4294967295))return null;
	let signed=value>2147483647?value-4294967296:value;
	return regulatory_number(signed,-10000,10000)?signed:null;
}
export function regulatory_location(freq) {
	if(freq==2484)return {band:2,channel:14};
	if(freq>=2412 && freq<=2472 && (freq-2407)%5==0)return {band:2,channel:(freq-2407)/5};
	if(freq>=4910 && freq<=4980 && (freq-4000)%5==0)return {band:5,channel:(freq-4000)/5};
	if(freq>=5005 && freq<=5920 && (freq-5000)%5==0)return {band:5,channel:(freq-5000)/5};
	if(freq==5935)return {band:6,channel:2};
	if(freq>=5955 && freq<=7115 && (freq-5950)%5==0)return {band:6,channel:(freq-5950)/5};
	if(freq>=58320 && freq<=70200 && (freq-56160)%2160==0)return {band:60,channel:(freq-56160)/2160};
	return {band:null,channel:null};
}
function frequencies(raw,issues) {
	let result={status:'unavailable',truncated:false,items:[]},invalid=false,seen={},count=0,
		allowed=[...REGULATORY_FLAGS,'freq','offset','max_tx_power','dfs_state','dfs_time','dfs_cac_time','psd','wmm'];
	if(type(raw?.wiphy_bands)!='array') { regulatory_add(issues,'frequencies_unavailable');return result; }
	if(length(raw.wiphy_bands)>16) { invalid=true;result.truncated=true; }
	for(let band in slice(raw.wiphy_bands,0,16)) {
		if(band===null)continue;
		if(type(band)!='object' || type(band.freqs)!='array') { invalid=true;continue; }
		if(length(band.freqs)>4096) { invalid=true;result.truncated=true; }
		for(let entry in slice(band.freqs,0,4096)) {
			if(entry===null)continue;
			count++;
			if(type(entry)!='object' || !regulatory_number(entry.freq,100,100000) || seen[''+entry.freq]) { invalid=true;continue; }
			seen[''+entry.freq]=true;
			if(length(result.items)>=256) { result.truncated=true;continue; }
			let flags=[],flags_known=true;
			for(let flag in REGULATORY_FLAGS) {
				if(index(keys(entry),flag)<0)continue;
				if(type(entry[flag])!='bool') { flags_known=false;invalid=true; }
				else if(entry[flag])push(flags,flag);
			}
			if(length(filter(keys(entry),key=>index(allowed,key)<0))) { flags_known=false;invalid=true;regulatory_add(issues,'frequency_fields_unknown'); }
			let loc=regulatory_location(entry.freq),power=regulatory_signed_mbm(entry.max_tx_power),radar=index(flags,'radar')>=0,
				dfs=index(keys(entry),'dfs_state')>=0 ? (regulatory_number(entry.dfs_state,0,2)?['usable','unavailable','available'][entry.dfs_state]:'unknown') : radar?'unknown':null;
			if(loc.band===null) { invalid=true;regulatory_add(issues,'unsupported_band'); }
			if(power===null) { invalid=true;regulatory_add(issues,index(keys(entry),'max_tx_power')>=0?'frequency_power_invalid':'frequency_power_unavailable'); }
			if(dfs=='unknown') { invalid=true;regulatory_add(issues,'frequency_dfs_unknown'); }
			let offset=entry.offset==null?null:regulatory_number(entry.offset,0,999)?entry.offset:null,
				age=entry.dfs_time==null?null:regulatory_number(entry.dfs_time,0,4294967295)?entry.dfs_time:null,
				cac=entry.dfs_cac_time==null?null:regulatory_number(entry.dfs_cac_time,0,4294967295)?entry.dfs_cac_time:null,
				psd=entry.psd==null?null:regulatory_number(entry.psd,-128,127)?entry.psd:null;
			if(entry.offset!=null && offset===null) { invalid=true;regulatory_add(issues,'frequency_offset_invalid'); }
			if(entry.psd!=null && psd===null) { invalid=true;regulatory_add(issues,'frequency_psd_invalid'); }
			if(entry.dfs_time!=null && age===null || entry.dfs_cac_time!=null && cac===null) { invalid=true;regulatory_add(issues,'frequency_dfs_invalid'); }
			push(result.items,{frequency_mhz:entry.freq,frequency_offset_khz:offset,band:loc.band,channel:loc.channel,
				flags,flags_known,max_tx_power_mbm:power,dfs_state:dfs,dfs_age_ms:age,dfs_cac_ms:cac,psd_dbm:psd});
		}
	}
	if(invalid)regulatory_add(issues,'frequencies_invalid');
	if(result.truncated)regulatory_add(issues,'frequencies_truncated');
	if(!length(result.items))regulatory_add(issues,'frequencies_empty');
	result.status=regulatory_status(!invalid && !result.truncated && count>0 && length(result.items)>0,length(result.items)>0);
	return result;
}
function regulatory(raw,global,index,country,issues) {
	let value=regulatory_empty(null,null,country).regulatory;
	if(country!==null && !regulatory_country(country))regulatory_add(issues,'configured_country_invalid');
	if(type(raw)=='object' && index !== null && 'wiphy' in raw && raw.wiphy!==index)
		die('target_changed: Regulatory response belongs to another PHY');
	if(type(raw)=='object' && regulatory_country(raw.reg_alpha2)) { value.alpha2=raw.reg_alpha2;value.scope='wiphy' in raw?'device':'global_fallback'; }
	else regulatory_add(issues,raw===null?'regulatory_unavailable':'regulatory_invalid');
	if(type(global)=='object' && !('wiphy' in global) && regulatory_country(global.reg_alpha2))value.global_alpha2=global.reg_alpha2;
	else regulatory_add(issues,global===null?'global_regulatory_unavailable':'global_regulatory_invalid');
	value.country_match=value.configured_country!==null && value.alpha2!==null?value.configured_country==value.alpha2:null;
	value.status=regulatory_status(value.alpha2!==null && value.global_alpha2!==null,value.alpha2!==null || value.global_alpha2!==null);
	return value;
}
function interface_identity(value,target,phyindex) {
	if(type(value)!='object')return false;
	if(value.wiphy!==phyindex || value.dev!==target.ifname || value.ifname!==target.ifname)
		die('target_changed: Actual interface or PHY mapping changed');
	return true;
}
function current(raw,target,issues) {
	let result=regulatory_empty_current();
	if(type(raw)!='object') { regulatory_add(issues,'current_unavailable');return result; }
	result.interface=target.ifname;
	if('mlo_links' in raw || 'mlo_link_id' in raw || 'mld_addr' in raw) { result.mlo=true;regulatory_add(issues,'mlo_unsupported');return result; }
	let width=['20_noht','20','40','80','80p80','160','unknown','unknown','unknown','unknown','unknown','unknown','unknown','320'];
	result.frequency_mhz=regulatory_number(raw.wiphy_freq,100,100000)?raw.wiphy_freq:null;
	result.channel_width=regulatory_number(raw.channel_width,0,13)?width[raw.channel_width]:raw.channel_width==null?null:'unknown';
	result.center_freq1_mhz=regulatory_number(raw.center_freq1,100,100000)?raw.center_freq1:null;
	result.center_freq2_mhz=regulatory_number(raw.center_freq2,100,100000)?raw.center_freq2:null;
	result.txpower_mbm=regulatory_signed_mbm(raw.wiphy_tx_power_level);
	let complete=result.frequency_mhz!==null && result.channel_width!==null && result.channel_width!='unknown' &&
		result.center_freq1_mhz!==null && result.txpower_mbm!==null &&
		(index(['80p80'],result.channel_width)<0 || result.center_freq2_mhz!==null);
	if(!complete)regulatory_add(issues,'current_incomplete');
	if(raw.wiphy_freq!=null && result.frequency_mhz===null || raw.channel_width!=null && result.channel_width=='unknown' ||
		raw.center_freq1!=null && result.center_freq1_mhz===null || raw.center_freq2!=null && raw.center_freq2!==0 && result.center_freq2_mhz===null ||
		raw.wiphy_tx_power_level!=null && result.txpower_mbm===null)regulatory_add(issues,'current_invalid');
	result.status=regulatory_status(complete,result.frequency_mhz!==null || result.txpower_mbm!==null);
	return result;
}
export function regulatory_request(input) {
	let idle=input?.schema===2;
	if(!regulatory_fields(input,idle ? ['schema','radio','phy','phyindex','configured_country','interfaces','phy_binding'] :
		['schema','radio','phy','phyindex','configured_country','interfaces']) || index([1,2],input.schema)<0 ||
		!regulatory_name(input.radio,64) || !regulatory_name(input.phy,63) || !regulatory_number(input.phyindex,0,2147483647) ||
		input.configured_country!==null && !regulatory_country(input.configured_country) ||
		type(input.interfaces)!='array' || (!idle && !length(input.interfaces)) || length(input.interfaces)>4 ||
		idle && (length(input.interfaces) || !regulatory_valid_phy_binding(input.phy_binding) ||
			input.phy_binding.phy!=input.phy || input.phy_binding.phyindex!=input.phyindex))
		die('invalid_request: Invalid private regulatory target');
	let names=[];
	for(let target in input.interfaces) {
		if(!regulatory_fields(target,['ifname','binding']) || !regulatory_name(target.ifname,15) || !regulatory_valid_binding(target.binding) ||
			target.binding.phy!==input.phy || target.binding.phyindex!==input.phyindex || index(names,target.ifname)>=0)
			die('invalid_request: Invalid private regulatory interface binding');
		push(names,target.ifname);
	}
	return clone(input);
}
// io.get accepts symbolic fixed GET operations only. The executable translates
// GET_INTERFACE to {dev: numeric_ifindex}, the official DT_NETDEV attribute.
// Original raw responses stay in this short-lived process and never stdout.
export function regulatory_query(input,io) {
	let target=regulatory_request(input),start=io.started_at ?? io.now();
	if(!regulatory_number(start,0,9007199254738991))die('read_failed: Monotonic query clock is unavailable');
	let deadline=start+2000,last_now=start;
	function budget() { let now=io.now();if(!regulatory_number(now,0,9007199254740991) || now<last_now || now>=deadline)die('budget_exceeded: Regulatory query exceeded its deadline');last_now=now; }
	function bindings() {
		budget();
		if(target.schema===2 && !equal(io.phy_binding?.(target.phy),target.phy_binding))
			die('target_changed: Actual kernel PHY binding changed');
		for(let entry in target.interfaces)if(!equal(io.binding(entry.ifname),entry.binding))die('target_changed: Actual kernel interface binding changed');budget();
	}
	function get(command,attrs) { budget();let value=null;try { value=io.get(command,attrs); }catch(e) {}budget();bindings();return type(value)=='object'?clone(value):null; }
	bindings();let device_before=get('GET_REG',{wiphy:target.phyindex}),global_before=get('GET_REG',{}),
		physical=get('GET_WIPHY',{wiphy:target.phyindex,split_wiphy_dump:true}),observed=[],issues=[];
	if(physical && (physical.wiphy!==target.phyindex || physical.wiphy_name!==target.phy))die('target_changed: Wiphy result does not match the actual kernel binding');
	for(let entry in target.interfaces) { let raw=get('GET_INTERFACE',{dev:entry.binding.ifindex});if(raw)interface_identity(raw,entry,target.phyindex);push(observed,raw); }
	let device_after=get('GET_REG',{wiphy:target.phyindex}),global_after=get('GET_REG',{});
	if(!equal(device_before,device_after) || !equal(global_before,global_after))die('target_changed: Regulatory domain changed during the query');
	let currents=[],changed=false;
	for(let n=0;n<length(target.interfaces);n++) {
		let entry=target.interfaces[n],last=get('GET_INTERFACE',{dev:entry.binding.ifindex});if(last)interface_identity(last,entry,target.phyindex);
		let first=current(observed[n],entry,issues),final=current(last,entry,issues);
		if(!equal(first,final))changed=true;
		push(currents,final);
	}
	bindings();let row=regulatory_empty(target.radio,target.phy,target.configured_country);
	row.regulatory=regulatory(device_after,global_after,target.phyindex,target.configured_country,issues);
	row.frequencies=frequencies(physical,issues);
	let reliable=filter(currents,value=>value.status!='unavailable'),ambiguous=length(uniq(map(reliable,value=>sprintf('%J',[
		value.frequency_mhz,value.channel_width,value.center_freq1_mhz,value.center_freq2_mhz,value.txpower_mbm]))))>1;
	if(changed || ambiguous || length(filter(currents,value=>value.mlo))) {
		row.current=regulatory_empty_current();row.current.mlo=length(filter(currents,value=>value.mlo))>0;
		regulatory_add(issues,changed?'current_changed':ambiguous?'ambiguous_current':'mlo_unsupported');
	} else row.current=currents[0] || regulatory_empty_current();
	if(!length(currents))regulatory_add(issues,'no_running_interface');
	if(length(filter(currents,value=>value.status!='complete')))regulatory_add(issues,'interfaces_current_incomplete');
	row.issues=issues;row.complete=!length(issues) && row.regulatory.status=='complete' && row.frequencies.status=='complete' && row.current.status=='complete';
	row.status=regulatory_status(row.complete,row.regulatory.status!='unavailable' || row.frequencies.status!='unavailable' || row.current.status!='unavailable');
	let result={schema:1,source:'nl80211',status:row.status,write_approval:false,transport_complete:null,truncated:row.frequencies.truncated,...row};
	while(length(sprintf('%J',result))>60000 && length(result.frequencies.items)) {
		budget();let items=result.frequencies.items;
		result.frequencies.items=slice(items,0,int(length(items)*3/4));result.frequencies.truncated=true;result.truncated=true;result.complete=false;result.status='partial';
		result.frequencies.status=length(result.frequencies.items)?'partial':'unavailable';regulatory_add(result.issues,'result_truncated');
	}
	budget();if(length(sprintf('%J',result))>65536)die('result_too_large: Regulatory result exceeds its limit');
	return result;
}
