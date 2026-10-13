// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as crypto from 'mesh_crypto';
import { clone,equal,valid_text } from './model.uc';
import { engine } from './transaction.uc';
function stable(raw){let i=json(raw);delete i.agent;return sprintf('%J',i);}
export function standby_bootstrap(points) {
	if(type(points)!='array' || length(points)>8)die('invalid_bootstrap: Invalid signed Root AP identities');
	for(let p in points)if(type(p)!='object' || !equal(sort(keys(p)),['bssid','ssid']) ||
		!valid_text(p.ssid,1,32) || !match(p.bssid || '',/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/))
		die('invalid_bootstrap: Invalid signed Root AP identity');
	return clone(points);
}
export function standby_capture(scope){
	let i=json(scope.identity),s=json(scope.state),b=i.binding,w=s.saved_intent?.wifi;
	if(i.role!='ap' || i.joining || i.handoff || i.departing || !b ||
		crypto.key_fingerprint(scope.key)!=i.fingerprint || i.id!=substr(i.fingerprint,0,32) ||
		crypto.fingerprint(scope.network_ca)!=b.ca_fingerprint || !crypto.verify_leaf(scope.network_ca,scope.cert,scope.key,i.id) ||
		w?.enabled!==true || !valid_text(w.ssid,1,32) || !valid_text(w.key,8,63))
		die('standby_unavailable: Restored AP has no authenticated Wi-Fi recovery path');
	let a=s.active,verified=engine({load:()=>clone(s),snapshot:()=>json(scope.snapshot)}).restoration_committed(a?.id,a?.request_id);
	if(!verified)die('standby_unavailable: Complete AP restoration is not verified');
	let points=filter(standby_bootstrap(i.bootstrap || []),p=>p.ssid==w.ssid);
	if(!length(points))die('standby_unavailable: Authenticated Root AP BSSID is unavailable');
	return {ssid:w.ssid,password:w.key,bssids:map(points,p=>p.bssid),code:{address:b.address,fingerprint:b.ca_fingerprint,token:sprintf('%064d',0)},
		ref:{identity:crypto.sha256(stable(scope.identity)),state:crypto.sha256(scope.state),snapshot:crypto.sha256(scope.snapshot),
			controller_id:b.controller_id,network_id:b.network_id}};
}
export function standby_proof(scope,config,started){
	let message=join('\n',['mesh-manager/standby/v1',crypto.sha256(scope.identity),crypto.sha256(scope.state),
		crypto.sha256(scope.snapshot),crypto.sha256(config),scope.boot,''+started])+'\n';
	return crypto.hmac(crypto.sha256(scope.key),message);
}
export function standby_authority(initial,current,journal){
	let i=current.identity,ref=initial.standby;
	if(initial.mode!='standby' || initial.boot!==current.boot || type(ref)!='object' || !equal(sort(keys(ref)),
		sort(['identity','state','snapshot','controller_id','network_id'])) || i?.role!='ap' || i.joining || i.handoff || i.departing ||
		current.key!==initial.key || current.cert!==initial.cert || current.network_ca!==initial.network_ca ||
		current.join_ca!==initial.join_ca || i.binding?.controller_id!=ref.controller_id || i.binding?.network_id!=ref.network_id ||
		crypto.sha256(stable(current.raw_identity || sprintf('%J',i)))!=ref.identity)return null;
	let s=json(journal);
	if(crypto.sha256(journal)==ref.state)return {standby:clone(ref),binding:clone(i.binding)};
	// A signed Root enable is prepared while the transport is live. Its apply
	// callback closes this actor before any managed wireless reload.
	let a=s.active,agent=i.agent;
	if(s.paused===true && a?.kind=='configure' && a.mesh_enabled===true && a.status=='staged' &&
		agent?.mesh===true && a.request_id==agent.transaction)
		return {standby:clone(ref),binding:clone(i.binding)};
	return null;
}
