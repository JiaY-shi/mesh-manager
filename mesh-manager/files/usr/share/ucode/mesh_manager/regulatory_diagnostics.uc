// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal } from './model.uc';
import { job_token } from './rpc_jobs.uc';
import { radio_targets } from './radio_diagnostics.uc';
import { REGULATORY_FLAGS, REGULATORY_ISSUES, regulatory_number as number, regulatory_name as name,
	regulatory_country as country, regulatory_fields as fields, regulatory_add as add,
	regulatory_status as status, regulatory_empty, regulatory_empty_current, regulatory_valid_binding, regulatory_location } from './regulatory_worker.uc';

function nullable(value,min,max) { return value===null || number(value,min,max); }
function raw(snapshot) { return {wireless:snapshot?.wireless,netifd:snapshot?.netifd,bindings:snapshot?.bindings}; }
function valid_axis(value) { return index(['complete','partial','unavailable'],value)>=0; }
function projected(value,target) {
	if(!fields(value,['schema','source','status','write_approval','transport_complete','truncated','radio','phy',
		'complete','regulatory','current','frequencies','issues']) || value.schema!==1 || value.source!='nl80211' ||
		value.write_approval!==false || value.transport_complete!==null || !valid_axis(value.status) ||
		type(value.complete)!='bool' || type(value.truncated)!='bool' || value.radio!==target.radio || value.phy!==target.phy ||
		type(value.issues)!='array' || length(value.issues)>length(REGULATORY_ISSUES) || length(uniq(value.issues))!=length(value.issues) ||
		length(filter(value.issues,code=>type(code)!='string' || index(REGULATORY_ISSUES,code)<0)))return null;
	let reg=value.regulatory,current=value.current,freq=value.frequencies;
	if(!fields(reg,['status','configured_country','alpha2','scope','global_alpha2','country_match','self_managed']) || !valid_axis(reg.status) ||
		reg.configured_country!==target.configured_country || reg.alpha2!==null && !country(reg.alpha2) ||
		reg.global_alpha2!==null && !country(reg.global_alpha2) || index(['device','global_fallback','unavailable'],reg.scope)<0 ||
		reg.self_managed!==null || reg.country_match!==null && type(reg.country_match)!='bool' ||
		(reg.scope=='unavailable')!==(reg.alpha2===null) ||
		reg.country_match!==(reg.configured_country!==null && reg.alpha2!==null?reg.configured_country==reg.alpha2:null))return null;
	if(reg.status!==status(reg.alpha2!==null && reg.global_alpha2!==null,reg.alpha2!==null || reg.global_alpha2!==null))return null;
	if(!fields(current,['status','source','interface','frequency_mhz','channel_width','center_freq1_mhz','center_freq2_mhz','txpower_mbm','mlo']) ||
		!valid_axis(current.status) || current.source!='driver_reported' || type(current.mlo)!='bool' ||
		current.interface!==null && !length(filter(target.interfaces,entry=>entry.ifname==current.interface)) ||
		!nullable(current.frequency_mhz,100,100000) || !nullable(current.center_freq1_mhz,100,100000) ||
		!nullable(current.center_freq2_mhz,100,100000) || !nullable(current.txpower_mbm,-10000,10000) ||
		current.channel_width!==null && index(['20_noht','20','40','80','80p80','160','320','unknown'],current.channel_width)<0 ||
		current.mlo && (current.frequency_mhz!==null || current.channel_width!==null || current.center_freq1_mhz!==null ||
			current.center_freq2_mhz!==null || current.txpower_mbm!==null))return null;
	let current_complete=!current.mlo && current.interface!==null && current.frequency_mhz!==null && current.channel_width!==null &&
		current.channel_width!='unknown' && current.center_freq1_mhz!==null && current.txpower_mbm!==null &&
		(current.channel_width!='80p80' || current.center_freq2_mhz!==null);
	if(current.status!==status(current_complete,current.frequency_mhz!==null || current.txpower_mbm!==null) ||
		current.interface===null && (current.frequency_mhz!==null || current.channel_width!==null || current.center_freq1_mhz!==null ||
			current.center_freq2_mhz!==null || current.txpower_mbm!==null))return null;
	if(!fields(freq,['status','truncated','items']) || !valid_axis(freq.status) || type(freq.truncated)!='bool' ||
		type(freq.items)!='array' || length(freq.items)>256 || value.truncated!==freq.truncated)return null;
	let seen={};
	for(let item in freq.items) {
		if(!fields(item,['frequency_mhz','frequency_offset_khz','band','channel','flags','flags_known','max_tx_power_mbm',
			'dfs_state','dfs_age_ms','dfs_cac_ms','psd_dbm']) || !number(item.frequency_mhz,100,100000) || seen[''+item.frequency_mhz] ||
			!nullable(item.frequency_offset_khz,0,999) || item.band!==null && index([2,5,6,60],item.band)<0 ||
			!nullable(item.channel,1,233) || type(item.flags_known)!='bool' || type(item.flags)!='array' ||
			length(item.flags)>length(REGULATORY_FLAGS) || length(uniq(item.flags))!=length(item.flags) ||
			length(filter(item.flags,flag=>type(flag)!='string' || index(REGULATORY_FLAGS,flag)<0)) ||
			!nullable(item.max_tx_power_mbm,-10000,10000) || item.dfs_state!==null && index(['usable','unavailable','available','unknown'],item.dfs_state)<0 ||
			!nullable(item.dfs_age_ms,0,4294967295) || !nullable(item.dfs_cac_ms,0,4294967295) || !nullable(item.psd_dbm,-128,127))return null;
		let loc=regulatory_location(item.frequency_mhz);
		if(item.band!==loc.band || item.channel!==loc.channel || index(item.flags,'radar')>=0 && item.dfs_state===null)return null;
		seen[''+item.frequency_mhz]=true;
	}
	if((freq.status=='unavailable')!==(length(freq.items)==0) || freq.status=='complete' && (freq.truncated ||
		length(filter(freq.items,item=>!item.flags_known || item.band===null || item.channel===null || item.max_tx_power_mbm===null || item.dfs_state=='unknown'))))return null;
	let complete=!length(value.issues) && !freq.truncated && reg.status=='complete' && current.status=='complete' && freq.status=='complete';
	if(value.complete!==complete || value.status!==status(complete,reg.status!='unavailable' || current.status!='unavailable' || freq.status!='unavailable'))return null;
	return {radio:value.radio,phy:value.phy,status:value.status,complete:value.complete,
		regulatory:clone(reg),current:clone(current),frequencies:clone(freq),issues:clone(value.issues)};
}
function helper(result,target) {
	let row=regulatory_empty(target.radio,target.phy,target.configured_country);row.issues=['helper_unavailable'];
	if(result?.code==-2)die('request_timeout: Regulatory helper exceeded its deadline');
	if(index([0,1],result?.code)<0 || type(result.stdout)!='string' || !length(result.stdout) || length(result.stdout)>65536)return row;
	let value;try {value=json(result.stdout);}catch(e){return row;}
	if(result.code==1) {
		if(!fields(value,['schema','status','reason']) || value.schema!==1 || value.status!='unavailable' ||
			index(['invalid_request','backend_unavailable','read_failed','result_too_large','target_changed','budget_exceeded'],value.reason)<0)return row;
		if(value.reason=='target_changed')die('target_changed: Actual regulatory target changed');
		if(value.reason=='budget_exceeded')die('request_timeout: Regulatory helper exceeded its deadline');
		row.issues=['helper_'+value.reason];return row;
	}
	return projected(value,target) || row;
}
export function local_regulatory(args,io) {
	if(!fields(args,['check','node_id']) || args.check!='local_regulatory' || !job_token(args.node_id))
		die('invalid_request: Invalid local regulatory diagnostic arguments');
	let start=io.now(),deadline=start+20000,last_now=start,identity=clone(io.identity()),boot=io.boot();
	if(!number(start,0,9007199254720991))die('request_timeout: Monotonic clock is unavailable');
	if(identity?.id!==args.node_id || !job_token(identity.id) || type(boot)!='string' || !length(boot))
		die('target_unavailable: Local regulatory identity is unavailable');
	function budget(required) { let now=io.now();if(!number(now,0,9007199254740991) || now<last_now || now>=deadline || deadline-now<required)
		die('request_timeout: Local regulatory diagnostics exceeded their deadline');last_now=now; }
	budget(0);let before=clone(io.snapshot(deadline,'before')),captured=clone(raw(before)),targets=radio_targets(before),rows=[];
	for(let plan in targets.radios) {
		budget(0);let configured=before.wireless?.[plan.radio]?.values?.country ?? null,
			selected=filter(plan.interfaces,iface=>before.netifd?.[plan.radio]?.up===true && regulatory_valid_binding(before.bindings?.[iface.ifname])),
			binding=before.bindings?.[selected[0]?.ifname],row=regulatory_empty(name(plan.radio,64)?plan.radio:null,binding?.phy || null,country(configured)?configured:null),
			consistent=length(selected) && !length(filter(selected,iface=>before.bindings[iface.ifname].phy!==binding.phy ||
				before.bindings[iface.ifname].phyindex!==binding.phyindex));
		if(!name(plan.radio,64) || !consistent)row.issues=[length(selected)?'mapping_unavailable':'no_running_interface'];
		else {
			let target={schema:1,radio:plan.radio,phy:binding.phy,phyindex:binding.phyindex,configured_country:country(configured)?configured:null,
				interfaces:map(selected,iface=>({ifname:iface.ifname,binding:clone(before.bindings[iface.ifname])}))};
			budget(2500);row=helper(io.run(['/usr/bin/ucode','/usr/libexec/mesh-manager-radio-regulatory'],sprintf('%J',target),2500),target);budget(0);
		}
		if(configured!==null && !country(configured))add(row.issues,'configured_country_invalid');
		if(!plan.interfaces_complete || length(selected)!=length(plan.interfaces))add(row.issues,plan.interfaces_truncated?'interfaces_truncated':'interfaces_incomplete');
		if(length(row.issues))row.complete=false;
		row.status=status(row.complete,row.regulatory.status!='unavailable' || row.current.status!='unavailable' || row.frequencies.status!='unavailable');push(rows,row);
	}
	budget(0);let after=clone(io.snapshot(deadline,'after'));budget(0);
	if(!equal(captured,raw(after)) || !equal(identity,io.identity()) || boot!==io.boot())
		die('target_changed: Original configuration, identity or actual kernel mapping changed');
	for(let row in rows)if(row.phy!==null && length(filter(rows,other=>other.phy===row.phy))>1) {
		row.current=regulatory_empty_current();row.complete=false;add(row.issues,'shared_phy_mapping');
		row.status=status(false,row.regulatory.status!='unavailable' || row.frequencies.status!='unavailable');
	}
	let result={schema:1,scope:'local_regulatory',source:'nl80211',node_id:identity.id,observed_at:io.time(),observed_uptime_ms:io.now(),boot_id:boot,
		status:'unavailable',complete:false,radio_total:targets.radio_total,radio_limit:8,truncated:targets.truncated,
		write_approval:false,transport_complete:null,radios:rows};
	while(length(sprintf('%J',result))>65536) {
		budget(0);
		let largest=null;for(let row in rows)if(length(row.frequencies.items)>length(largest?.frequencies?.items || []))largest=row;
		if(!largest)die('result_too_large: Regulatory diagnostics exceed their result limit');
		largest.frequencies.items=slice(largest.frequencies.items,0,int(length(largest.frequencies.items)*3/4));
		largest.complete=false;largest.frequencies.truncated=true;largest.frequencies.status=length(largest.frequencies.items)?'partial':'unavailable';
		largest.status=status(false,largest.regulatory.status!='unavailable' || largest.current.status!='unavailable' || length(largest.frequencies.items)>0);
		add(largest.issues,'result_truncated');result.truncated=true;
	}
	result.truncated=result.truncated || length(filter(rows,row=>row.frequencies.truncated))>0;
	result.complete=!result.truncated && length(rows)>0 && !length(filter(rows,row=>!row.complete));
	result.status=status(result.complete,length(filter(rows,row=>row.status!='unavailable'))>0);budget(0);
	if(length(sprintf('%J',result))>65536)die('result_too_large: Regulatory diagnostics exceed their result limit');
	return result;
}
