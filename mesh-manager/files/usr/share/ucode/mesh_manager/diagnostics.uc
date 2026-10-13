// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { hmac } from 'mesh_crypto';

// Export is an allowlist, not a copy of status with a few secrets deleted.
// Free-form messages, names, addresses, configuration and future fields stay private.
function boolean(value) { return type(value)=='bool' ? value : null; }
function number(value,minimum,maximum) {
	return index(['int','double'],type(value))>=0 && value>=minimum && value<=maximum ? value : null;
}
function choice(value,allowed) { return index(allowed,value)>=0 ? value : 'unknown'; }
function count(value,limit) { return type(value)=='array' ? min(length(value),limit) : null; }
function certificate(value) {
	return {status:choice(value?.status,['valid','expiring','expired','not_yet_valid','invalid',
		'identity_mismatch','untrusted','clock_invalid','missing','unavailable','not_enrolled']),
		remaining_days:number(value?.remaining_days,0,36525)};
}
function checks(value) {
	if (type(value)!='array') return null;
	let result={passed:0,failed:0,unknown:0,truncated:length(value)>256};
	for (let row in slice(value,0,256)) result[row?.ok===true ? 'passed' : row?.ok===false ? 'failed' : 'unknown']++;
	return result;
}
function transaction(value) {
	if(type(value)!='object')return null;
	return {status:choice(value.status || value.phase,['staged','preflight','ready','applying','apply_requested',
		'awaiting_confirm','committed','complete','partial','failed','rolling_back','rollback_requested','rolled_back',
		'rollback_conflict','expired','cancelled']),
		version:number(value.version,0,2147483647),remaining_seconds:number(value.remaining,0,86400),
		has_failure:value.failure!=null || value.error!=null,conflicts:count(value.conflicts,2048)};
}
export function redacted_diagnostics(data,secret,wall) {
	if(type(data)!='object' || type(secret)!='string' || !match(secret,/^[0-9a-f]{64}$/))
		die('invalid_request: Invalid diagnostic export input');
	function alias(id) {
		return type(id)=='string' && match(id,/^[0-9a-f]{32}$/) ? 'node-'+substr(hmac(secret,id),0,16) : null;
	}
	let cap=data.capabilities || {},local=data.local || {},cluster=data.cluster || {},identity=cluster.identity || {},
		roaming=local.roaming || {},members=type(cluster.members)=='array' ? cluster.members : [],
		radios=type(local.dfs)=='array' ? local.dfs : [],dependencies={};
	for(let name in ['bus','daemon','dnsmasq','firewall','hostapd','sae','ft','mesh','mesh_control','mesh_acl','usteer','dawn'])
		dependencies[name]=boolean(cap[name]);
	let result={schema:2,redacted:true,generated_at:number(wall,0,4102444800),
		local:{node:alias(identity.id),controller:alias(identity.controller_id),role:choice(identity.role,['root','ap','unbound']),
			gateway:choice(identity.gateway,['router','bridge']),mesh_enabled:boolean(data.mesh_enabled),
			transaction_version:number(data.version,0,2147483647),intent_version:number(cluster.version,0,2147483647),
			drift_count:count(data.drift,2048),transaction:transaction(data.active),health:checks(data.health?.checks)},
		dependencies,
		certificates:{ca:certificate(local.certificates?.ca),device:certificate(local.certificates?.device)},
		lan_services: {observed_at:number(local.lan_services?.observed_at,0,4102444800),
			checks:map(['lan_dhcp_configuration','lan_dhcp_service','lan_ipv6_service'],name=>({name,
				status:choice(filter(type(local.lan_services?.checks)=='array' ? local.lan_services.checks : [],
					c=>c?.name==name)[0]?.status,['ready','not_running','not_required','invalid_configuration','unavailable'])}))},
		backhaul:{active:choice(local.backhaul?.active,['wired','wireless','none']),
			wired_verified:boolean(local.backhaul?.wired),wireless_verified:boolean(local.backhaul?.wireless)},
		roaming:{backend:'usteer',installed:boolean(roaming.installed),managed:boolean(roaming.managed),
			requested:boolean(roaming.requested),running:boolean(roaming.running),healthy:boolean(roaming.healthy),
			supported:boolean(roaming.supported),missing_parameters:count(roaming.missing,64),health:checks(roaming.checks)},
		dfs:map(slice(radios,0,8),(radio,index)=>({radio:index+1,channel:number(radio?.channel,1,233),
			cac_active:boolean(radio?.cac_active),cac_seconds_left:number(radio?.cac_seconds_left,0,3600)})),
		cluster:{transaction:transaction(cluster.active),members:map(slice(members,0,64),member=>({node:alias(member?.id),
			authorized:boolean(member?.authorized),online:boolean(member?.online),mesh_paused:boolean(member?.mesh_paused),
			version:number(member?.version,0,2147483647),has_error:member?.error!=null}))},
		truncated:length(members)>64 || length(radios)>8};
	if(length(sprintf('%J',result))>32768)die('result_too_large: Diagnostic export exceeds its size limit');
	return result;
}
