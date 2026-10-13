// SPDX-License-Identifier: GPL-2.0-only
'use strict';

const RULES={recovery_unavailable:['error','diagnostics'],bus_unavailable:['error','diagnostics'],
	configuration_drift:['warning','nodes'],node_offline:['warning','nodes'],
	agent_unavailable:['warning','diagnostics'],agent_check_failed:['warning','diagnostics'],
	backhaul_unavailable:['error','backhaul'],backup_active:['warning','backhaul']};
function count(value) { return type(value)=='array' ? min(length(value),2048) : 0; }
function item(code,node,count) {
	return {code,node_id:node,severity:RULES[code][0],page:RULES[code][1],count:count || null};
}
export function recent_presence(seen,boot,now) {
	return type(seen)=='object' && seen.boot==boot && index(['int','double'],type(seen.seen))>=0 &&
		seen.seen>=0 && seen.seen<=now && now-seen.seen<15;
}
function path_alerts(path,mode,node) {
	if(path?.active=='none')return [item('backhaul_unavailable',node)];
	if(mode=='auto' && path?.active=='wireless')return [item('backup_active',node)];
	return [];
}
export function member_attention(member,online,mode) {
	if(member?.authorized!==true || member.mesh_paused===true)return [];
	if(online!==true)return [item('node_offline',member.id)];
	// A received disable report precedes the controller's final pause receipt.
	if(member.report?.mesh_enabled===false)return [];
	let result=path_alerts(member.report?.backhaul,mode,member.id),drift=count(member.report?.drift);
	if(drift)unshift(result,item('configuration_drift',member.id,drift));
	return result;
}
export function current_attention(data,boot,now,wall) {
	let items=[],total=0,cluster=data.cluster || {},role=cluster.identity?.role;
	function add(value) { total++;if(length(items)<128)push(items,value); }
	if(data.mesh_enabled===true) {
		if(data.capabilities?.daemon===false)add(item('recovery_unavailable',null));
		if(data.capabilities?.bus===false)add(item('bus_unavailable',null));
		let restoring=data.active?.kind=='release' && index(['applying','awaiting_confirm'],data.active.status)>=0;
		if(!restoring && count(data.drift))add(item('configuration_drift',null,count(data.drift)));
		if(index(['root','ap'],role)>=0 && now>=15) {
			let agent=cluster.agent;
			if(!recent_presence({boot:agent?.boot,seen:agent?.uptime},boot,now))add(item('agent_unavailable',null));
			else if(agent.ok===false && agent.error!='busy')add(item('agent_check_failed',null));
		}
		if(role=='ap')for(let alert in path_alerts(data.local?.backhaul,data.intent?.backhaul?.mode,null))add(alert);
		if(role=='root')for(let node in cluster.members || [])for(let alert in node.attention || [])add(alert);
	}
	return {items,total,truncated:total>128,observed_at:wall};
}
