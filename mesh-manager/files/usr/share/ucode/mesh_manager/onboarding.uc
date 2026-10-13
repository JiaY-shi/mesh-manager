// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import { connect } from 'ubus';
import { discover_wireless,scan_wireless } from './discovery.uc';
import { joining_code } from './invitation.uc';
import { onboard_projection, onboard_observation_authorized, onboard_permit_frame } from './onboard_session.uc';
import { approval_valid, approval_transport_valid } from './joining_exchange.uc';
import { handoff_state, handoff_transport_valid } from './first_handoff.uc';
import { resume_capture } from './enrollment_resume.uc';
import { standby_capture,standby_proof } from './standby.uc';

const DIR = '/var/run/mesh-manager-onboard';
const IFACE = 'mm-onboard';
function native() {
 let n=require('mesh_onboard');
 if(type(n?.read)!='function' || type(n?.scope)!='function')die('runtime_unavailable: Onboarding helper unavailable');
 return n;
}
function presence(path) {
 fs.error();
 let stat=fs.lstat(path),error=fs.error();
 return stat!=null ? 'present' : error=='No such file or directory' ? 'absent' : 'unavailable';
}
function same_scope(a,b) {
 if(type(a)!='object' || type(b)!='object' || a.error || b.error)return false;
 for(let key in ['identity','key','boot','tag','stamp','join_ca','network_ca','cert'])
  if(a[key]!==b[key])return false;
 return true;
}
function journal(n) {
 let value=n.journal();
 if(type(value)!='object' || value.error)die('runtime_unavailable: Initial journal unavailable');
 return value.raw;
}
export function onboarding_material_scope(n,expected,provider) {
 if(type(expected)!='object')die('identity_error: Bootstrap capture unavailable');
 let actual=n.scope();
 if(!('state' in expected) && expected?.snapshot==null)return actual;
 if(type(provider)!='function')die('runtime_unavailable: Full bootstrap context unavailable');
 let material=provider();
 if(!same_scope(actual,material) || !('state' in material) ||
  (expected.snapshot==null ? material.snapshot!=null : type(material.snapshot)!='string'))
  die('identity_error: Full bootstrap context changed');
 return material;
}
const material_scope=onboarding_material_scope;
function same_material(a,b) {
 return same_scope(a,b) && (!('state' in a) && a.snapshot==null ||
  ('state' in b) && a.state===b.state && a.snapshot===b.snapshot &&
  (!('cluster' in a) || 'cluster' in b && a.cluster===b.cluster));
}
function observation() {
 let n=native(),value=n.read();
 if(value?.verified===true && value.authority?.handoff==null || value?.resources_verified!==true)return value;
 let crypto=require('mesh_crypto'),scope=n.scope();
 value.verified=onboard_observation_authorized(value,scope,{ca:(pem,fp)=>type(pem)=='string' && crypto.fingerprint(pem)==fp,
  leaf:crypto.verify_leaf,digest:crypto.sha256,approval:approval_valid,transport_approval:approval_transport_valid,
  handoff_transport:(raw,ref)=>handoff_transport_valid(raw,journal(n),raw.boot,n.now(),ref)});
 return value;
}

function interface_name(value) {
	return type(value) == 'string' && match(value, /^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/);
}

export function station_config(ssid, bssid, password) {
	if (type(ssid) != 'string' || length(ssid) < 1 || length(ssid) > 32 ||
		!match(bssid || '', /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/) ||
		type(password) != 'string' || length(password) < 8 || length(password) > 63)
		die('invalid_wireless: Invalid onboarding Wi-Fi credentials');
	let encoded = '';
	for (let i = 0; i < length(ssid); i++) {
		let value = ord(substr(ssid, i, 1));
		if (value < 32 || value == 127)
			die('invalid_wireless: Invalid onboarding SSID');
		encoded += sprintf('%02x', value);
	}
	for (let i = 0; i < length(password); i++) {
		let value = ord(substr(password, i, 1));
		if (value < 32 || value > 126)
			die('invalid_wireless: Invalid onboarding Wi-Fi password');
	}
	let escaped = replace(replace(password, /\\/g, '\\\\'), /"/g, '\\"');
	return 'network={\n\tssid=' + encoded +
		'\n\tbssid=' + lc(bssid) + '\n\tpsk="' + escaped +
		'"\n\tkey_mgmt=WPA-PSK SAE\n}\n';
}

export function select_access_point(scan, request) {
	if (!interface_name(request?.device) ||
		!match(request?.bssid || '', /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/))
		die('invalid_wireless: Invalid scanned access point');
	let chosen = filter(scan?.access_points || [], (ap) =>
		ap.device == request.device && ap.bssid == lc(request.bssid) &&
		ap.ssid == request.ssid
	)[0];
	if (!chosen) die('stale_scan: Access point is no longer visible');
	return chosen;
}

export function association_connected(output, bssid) {
	return type(output) == 'string' &&
		lc(match(output, /^Connected to ([0-9a-fA-F:]{17}) /)?.[1] || '') == bssid;
}

export function validate_onboard_request(request) {
	if (request?.takeover !== true)
		die('takeover_required: Temporary Wi-Fi access requires consent');
	if (!interface_name(request.device)) die('invalid_wireless: Invalid scanned access point');
	let code = request.code ? joining_code(request.code) : null;
	station_config(request.ssid, request.bssid, request.password);
	return code;
}

// The idle-radio case must also be empty in the kernel. A missing netifd
// interface record cannot authorize changing a radio used by another actor.
export function onboarding_radio(point, status, info, interfaces) {
	let phy = info?.phy, idle = status?.[point.device];
	if (!match(phy || '', /^phy[0-9]{1,3}$/) || type(interfaces) != 'array' ||
		type(point.channel) != 'int' || point.channel < 1 || point.channel > 233)
		die('unsupported_radio: Radio mapping is unavailable');
	if (idle?.up === true && idle.config?.type == 'mac80211' &&
		type(idle.interfaces) == 'array' && !length(idle.interfaces)) {
		if (length(filter(interfaces, iface => iface.phy == phy)))
			die('channel_conflict: Selected idle radio has an existing wireless interface');
		return phy;
	}
	let matches = [];
	for (let radio in values(status || {}))
		if (radio.up === true)
			for (let iface in radio.interfaces || [])
				if (iface.ifname == point.device && iface.config?.mode == 'ap') push(matches, iface);
	if (length(matches) != 1 || !length(filter(interfaces, iface => iface.name == point.device && iface.phy == phy)))
		die('unsupported_radio: Radio mapping is unavailable');
	if (info.channel != point.channel)
		die('channel_conflict: Scanned Wi-Fi must share the active radio channel');
	return phy;
}

function kernel_interfaces() {
	fs.error();
	let names = fs.lsdir('/sys/class/net'), error = fs.error(), result = [];
	if (error || type(names) != 'array' || length(names) > 256)
		die('unsupported_radio: Wireless interfaces cannot be observed');
	for (let name in names) {
		fs.error();
		let path = fs.readlink('/sys/class/net/' + name + '/phy80211'), error = fs.error();
		if (error && error != 'No such file or directory')
			die('unsupported_radio: Wireless interfaces cannot be observed');
		if (path) push(result, { name, phy: fs.basename(path) });
	}
	return result;
}

// All read calls are observational. Unknown old directories/sessions are never
// silently adopted, repaired or cleared by rpcd's read ACL.
export function onboard_status() {
 let stored=presence(DIR);
 if(stored=='unavailable')return {active:true,connected:false,error:'runtime_unavailable'};
 if(stored=='absent') {
  let link=presence('/sys/class/net/'+IFACE);
  return link=='absent' ? {active:false} : {active:true,connected:false,error:link=='present' ? 'cleanup_conflict' : 'runtime_unavailable'};
 }
 try {return onboard_projection(observation());}
 catch(e){return {active:true,connected:false,error:'runtime_unavailable'};}
}
export function onboard_pending() {
 // Cheap fixed-path existence check for recovery scheduling, no native load.
 return presence(DIR)!='absent' || presence('/sys/class/net/'+IFACE)!='absent';
}
export function onboard_stop() {
 let stored=presence(DIR);
 if(stored=='unavailable')die('cleanup_conflict: Temporary storage could not be observed');
 if(stored=='absent') {
  if(presence('/sys/class/net/'+IFACE)!='absent')die('cleanup_conflict: Unknown temporary interface was preserved');
  return {active:false};
 }
 let stopped=native().stop();
 // The independent owner may finish teardown between our presence check and
 // its control reply. A remaining or unobservable resource still blocks apply.
 if(stopped!==true && (presence(DIR)!='absent' || presence('/sys/class/net/'+IFACE)!='absent'))
  die('cleanup_conflict: Temporary connection was not safely recovered');
 return {active:false};
}
export function onboarding_transport(address) {
 if(presence(DIR)!='present')return null;
 try {
  let value=observation(),view=onboard_projection(value);
  if(view.connected!==true || value?.controller!=address || !match(value.generation || '',/^[0-9a-f]{32}$/) ||
   !match(value.session_scope_tag || '',/^[0-9a-f]{64}$/) || !match(value.boot || '',/^[0-9a-f-]{36}$/) ||
   type(value.pid)!='int' || value.pid<1 || !match(value.start_ticks || '',/^[0-9]{1,20}$/) ||
   type(value.ifindex)!='int' || value.ifindex<1 || type(value.phy)!='int' || value.phy<0 ||
   !match(value.mac || '',/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/))return null;
  return {device:IFACE,controller:address,generation:value.generation,boot:value.boot,pid:value.pid,
   start_ticks:value.start_ticks,ifindex:value.ifindex,phy:value.phy,mac:value.mac,scope_tag:value.session_scope_tag};
 }catch(e){return null;}
}
export function onboarding_device(address) {
 return onboarding_transport(address)?.device || null;
}
export function onboard_capture() {
 let n=native(),started=n.now(),scope=n.scope();
 if(scope?.error || type(scope.identity)!='string' || type(started)!='int' || started<1)
  die('runtime_unavailable: Onboarding identity unavailable');
 return {scope,started};
}
/* Short-lock cancellation capture. Connection freshness and configuration
 * authority are deliberately independent of this private live-owner proof;
 * a stale owned actor may still be cancelled, while unknown objects remain. */
export function onboard_cleanup_capture() {
 let stored=presence(DIR);
 if(stored=='absent') {
  if(presence('/sys/class/net/'+IFACE)=='absent')return null;
  die('cleanup_conflict: Unknown temporary interface was preserved');
 }
 if(stored!='present')die('cleanup_conflict: Temporary storage could not be observed');
 let value=native().read();
 if(value?.owner_verified!==true || !match(value.generation || '',/^[0-9a-f]{32}$/) ||
  !match(value.boot || '',/^[0-9a-f-]{36}$/) || type(value.pid)!='int' || value.pid<1 ||
  !match(value.start_ticks || '',/^[0-9]{1,20}$/))
  die('cleanup_conflict: Temporary connection owner could not be verified');
 return {generation:value.generation,boot:value.boot,pid:value.pid,start_ticks:value.start_ticks};
}
/* Internal health-completion ownership capture. A live actor is not absent
 * merely because its lease/association observation has expired. */
export function onboarding_owned_transport(address) {
 let owner=onboard_cleanup_capture();if(owner==null)return null;
 let value=native().read();
 if(value?.owner_verified!==true || value.generation!==owner.generation || value.boot!==owner.boot ||
  value.pid!==owner.pid || value.start_ticks!==owner.start_ticks || type(value.ifindex)!='int' || value.ifindex<1 ||
  type(value.phy)!='int' || value.phy<0 || !match(value.mac || '',/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/) ||
  !match(value.session_scope_tag || '',/^[0-9a-f]{64}$/) || type(value.controller)!='string' ||
  address!=null && value.controller!==address)
  die('cleanup_conflict: Complete temporary transport owner unavailable');
 return {device:IFACE,controller:value.controller,generation:value.generation,boot:value.boot,pid:value.pid,
  start_ticks:value.start_ticks,ifindex:value.ifindex,phy:value.phy,mac:value.mac,scope_tag:value.session_scope_tag};
}
export function onboard_stop_owned(handle) {
 if(type(handle)!='object' || !match(handle.generation || '',/^[0-9a-f]{32}$/))return false;
 if(handle.boot!=null || handle.pid!=null || handle.start_ticks!=null) {
  if(!match(handle.boot || '',/^[0-9a-f-]{36}$/) || type(handle.pid)!='int' || handle.pid<1 ||
   !match(handle.start_ticks || '',/^[0-9]{1,20}$/))return false;
  return native().stop_generation(handle.generation,handle)===true;
 }
 return native().stop_generation(handle.generation)===true;
}
export function onboarding_resume_continues(capture,handle) {
 let transport=onboarding_transport(capture?.code?.address);
 return transport!=null && transport.generation===handle?.generation && transport.boot===capture?.scope?.boot &&
  transport.scope_tag===capture.scope.tag;
}
export function onboarding_authorize(handle,scope,checkpoint,expected_identity,timeout_ms,material_provider) {
 let n=native(),started=n.now(),actual=material_scope(n,scope,material_provider);
 if(!same_material(scope,actual) || type(timeout_ms)!='int' || timeout_ms<1 || timeout_ms>8000)return false;
 let value=n.read();
 if(value?.resources_verified!==true || value.generation!==handle?.generation || value.boot!==handle.boot ||
  value.session_scope_tag!==handle.scope_tag || value.pid!==handle.pid || value.start_ticks!==handle.start_ticks ||
  value.ifindex!==handle.ifindex || value.phy!==handle.phy || value.mac!==handle.mac || value.controller!==handle.controller)return false;
 let crypto=require('mesh_crypto'),frame=onboard_permit_frame(value,scope,checkpoint,expected_identity,
  {digest:crypto.sha256,hmac:crypto.hmac,approval:approval_valid});
 let remaining=min(timeout_ms,started+timeout_ms-n.now());
 return frame!=null && remaining>0 && n.permit(frame,scope,remaining)===true && n.now()<started+timeout_ms &&
  same_material(scope,material_scope(n,scope,material_provider));
}
function selected_radio(point) {
	let bus = connect(null, 2), info, status;
	try {
		info = bus?.call('iwinfo', 'info', { device: point.device });
		status = bus?.call('network.wireless', 'status', {});
	} catch (e) {}
	if (bus) bus.disconnect();
	return onboarding_radio(point, status, info, kernel_interfaces());
}
export function onboard_start(request,captured) {
 let n=native();captured=captured || onboard_capture();
 let started=captured.started,scope=captured.scope;
 if(scope?.error || type(scope.identity)!='string')die('runtime_unavailable: Onboarding identity unavailable');
 if(!same_scope(scope,n.scope()) || type(started)!='int' || started<1 || n.now()<started || n.now()>=started+60000)
  die('identity_error: Wireless onboarding approval changed');
 let identity=json(scope.identity);
	if (identity?.role != 'unbound' || identity?.joining || identity?.binding)
		die('already_bound: Wireless onboarding is only for an unbound AP');
	let code = validate_onboard_request(request);
 let
		point = select_access_point(discover_wireless(identity, null, null, request.device), request),
		config = station_config(point.ssid, point.bssid, request.password);
	if (fs.access(DIR) || fs.access('/sys/class/net/' + IFACE))
		die('already_active: Stop the previous wireless onboarding session first');
 let phy = selected_radio(point);
 let fresh=n.scope();
 if(!same_scope(fresh,scope) || n.now()>=started+60000)
  die('identity_error: Wireless onboarding approval changed');
 let result=n.launch({scope,started,code,controller:code?.address || null,mode:code ? null : 'discover',
  phy:int(substr(phy,3)),config,ssid:point.ssid,bssid:point.bssid});
 if(result?.error)die(result.error+': Temporary wireless onboarding failed');
 if(result?.connected!==true)die('onboarding_failed: Actual wireless association is unavailable');
 return {active:true,connected:true,ssid:result.ssid,remaining:result.remaining,controller:result.controller,generation:result.generation};
}
/* Internal same-request recovery. No RPC accepts these capture arguments and
 * normal onboard_start still rejects every already-pending request. */
export function onboard_resume_start(capture,attempt_deadline,material_provider) {
 let n=native(),scope=material_scope(n,capture?.scope,material_provider),started=n.now(),crypto=require('mesh_crypto');
 const verify={ca:(pem,fp)=>type(pem)=='string' && crypto.fingerprint(pem)==fp,leaf:crypto.verify_leaf,approval:approval_valid,key:crypto.key_fingerprint};
 let actual=resume_capture(scope,joining_code,verify);
 if(actual.error)die(actual.error+': Automatic wireless recovery is unavailable');
 if(!same_material(scope,capture?.scope) || type(attempt_deadline)!='int' || started+61100>=attempt_deadline)
  die('identity_error: Pending request recovery changed');
 let identity=actual.identity,scan=discover_wireless(identity,null,null,null,min(20,int((attempt_deadline-started)/1000))),
  points=filter(scan?.access_points || [],p=>p.ssid==identity.enrollment.ssid && (!identity.enrollment.bssid || p.bssid==identity.enrollment.bssid) &&
  (!identity.enrollment.device || p.device==identity.enrollment.device)),point=points[0];
 if(!point)die(scan?.available===false ? 'scan_unavailable: Wireless scan unavailable' : 'wireless_unavailable: Original Wi-Fi was not found');
 if(presence(DIR)!='absent' || presence('/sys/class/net/'+IFACE)!='absent')
  die('cleanup_conflict: Existing temporary resources were preserved');
 let phy=selected_radio(point);
 if(!same_material(scope,material_scope(n,scope,material_provider)) || n.now()>=attempt_deadline || n.now()+60000>attempt_deadline)
  die('identity_error: Pending request recovery changed or exhausted its budget');
 let result=n.launch({scope,started:n.now(),code:actual.code,mode:'resume',controller:actual.code.address,
  phy:int(substr(phy,3)),config:station_config(point.ssid,point.bssid,identity.enrollment.password),
  ssid:point.ssid,bssid:point.bssid});
 if(result?.error)die(result.error+': Temporary pending-request transport failed');
 if(result?.connected!==true || !match(result.generation || '',/^[0-9a-f]{32}$/))
  die('onboarding_failed: Actual pending-request transport was not verified');
 if(!same_material(scope,material_scope(n,scope,material_provider)) || n.now()>=attempt_deadline) {
  onboard_stop_owned({generation:result.generation});die('identity_error: Pending transport approval changed');
 }
 return result;
}
/* Initial AP only: neither staged/awaiting transactions nor configured or
 * deliberately paused APs acquire a cold bootstrap path. */
export function onboard_handoff_start(capture,attempt_deadline,material_provider) {
 let n=native(),scope=material_scope(n,capture?.scope,material_provider),started=n.now();
 if(!('state' in scope) || type(scope.snapshot)!='string' || !same_material(scope,capture?.scope) ||
  type(attempt_deadline)!='int' || started+81000>=attempt_deadline)
  die('identity_error: Initial handoff capture or whole startup budget changed');
 let phase=handoff_state(scope,scope.state,scope.snapshot,scope.boot,started);
 if(phase.stage!='configuring' || phase.restore!==true)die('identity_error: Cold initial handoff is blocked');
 let identity=json(scope.identity),code=joining_code(identity.enrollment.code),
  scan=scan_wireless(null,null,null,min(20,int((attempt_deadline-started)/1000))),
  points=filter(scan?.access_points || [],p=>p.ssid==identity.enrollment.ssid && (!identity.enrollment.bssid || p.bssid==identity.enrollment.bssid) &&
  (!identity.enrollment.device || p.device==identity.enrollment.device)),point=points[0];
 if(!point)die(scan?.available===false ? 'scan_unavailable: Wireless scan unavailable' : 'wireless_unavailable: Original Wi-Fi was not found');
 if(presence(DIR)!='absent' || presence('/sys/class/net/'+IFACE)!='absent')
  die('cleanup_conflict: Existing temporary resources were preserved');
 let phy=selected_radio(point);
 if(!same_material(scope,material_scope(n,scope,material_provider)) || n.now()+60000>=attempt_deadline)
  die('identity_error: Initial handoff changed or exhausted its startup budget');
 let result=n.launch({scope,started:n.now(),code,mode:'handoff',controller:code.address,
  phy:int(substr(phy,3)),config:station_config(point.ssid,point.bssid,identity.enrollment.password),
  ssid:point.ssid,bssid:point.bssid});
 if(result?.error)die(result.error+': Temporary initial handoff transport failed');
 if(result?.connected!==true || !match(result.generation || '',/^[0-9a-f]{32}$/))
  die('onboarding_failed: Actual initial handoff transport was not verified');
 if(!same_material(scope,material_scope(n,scope,material_provider)) || n.now()>=attempt_deadline) {
  onboard_stop_owned({generation:result.generation});die('identity_error: Initial handoff transport approval changed');
 }
 return result;
}

// The saved Mesh Wi-Fi supplies a finite control-only STA after exact original
// restoration. It has no durable UCI changes or default route and never joins
// a different controller. The original independent actor owns its cleanup.
export function onboard_standby_start(capture,material_provider) {
 let n=native(),scope=material_scope(n,capture,material_provider);
 if(type(n.begin_standby)!='function')die('standby_unavailable: Wireless recovery runtime is unavailable');
 let target=standby_capture(scope),identity=json(scope.identity),started=n.now(),
	 scan=scan_wireless(null,null,null,10),points=filter(scan?.access_points || [],p=>p.ssid==target.ssid && index(target.bssids,p.bssid)>=0),point,phy;
 for(let candidate in slice(points,0,8))try{phy=selected_radio(candidate);point=candidate;break;}catch(e){}
 if(!point)die('standby_unavailable: No compatible controller Wi-Fi channel was found');
 if(presence(DIR)!='absent' || presence('/sys/class/net/'+IFACE)!='absent')
  die('cleanup_conflict: Existing temporary wireless resources were preserved');
 if(!same_material(scope,material_scope(n,scope,material_provider)))die('identity_error: Restored wireless recovery changed');
 let config=station_config(point.ssid,point.bssid,target.password),actual_started=n.now();
 let result=n.launch({scope,started:actual_started,code:target.code,standby:target.ref,mode:'standby',
  proof:standby_proof(scope,config,actual_started),controller:target.code.address,
  phy:int(substr(phy,3)),config,ssid:point.ssid,bssid:point.bssid});
 if(result?.connected!==true)die((result?.error || 'standby_unavailable')+': Wireless recovery did not connect');
 return result;
}
export function onboard_standby_stop() {
 if(presence(DIR)!='present')return;
 let value=native().read();
 if(value?.authority?.standby==null)return;
 return onboard_stop();
}
