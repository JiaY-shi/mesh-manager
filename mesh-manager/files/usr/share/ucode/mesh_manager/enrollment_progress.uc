// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal, valid_text, canonical } from './model.uc';

const LIMIT=16384,MAX=2147483647,AGE=180000;
const FIELDS=['schema','boot','node_id','identity_tag','owner','revision','observed_uptime_ms',
 'phase','next_uptime_ms','cycle','status','error','candidates','access_points'];
const TRANSPORT_FIELDS=['transport','transport_error','transport_deadline'];
const HANDOFF_FIELDS=['handoff','handoff_error'];
const HANDOFF_STATES=['configuring','staged','awaiting_health','committed','blocked'];
const HANDOFF_ERRORS=['handoff_conflict','handoff_paused','handoff_recovery','handoff_unhealthy',
 'handoff_timeout','cleanup_conflict','storage_conflict','identity_error','storage_error','busy',
 'runtime_unavailable','peer_unavailable','internal_error','scan_unavailable','wireless_unavailable',
 'unsupported_radio','channel_conflict','onboarding_failed','protocol_error','not_authorized'];
const PATCH=['phase','next','cycle','status','error','candidates','access_points',...TRANSPORT_FIELDS,...HANDOFF_FIELDS];
const TRANSPORT=['restoring','verified','unavailable','requires_credentials'];
const TRANSPORT_ERRORS=['requires_credentials','target_changed','identity_error','runtime_unavailable',
 'peer_unavailable','network_unavailable','timeout','onboarding_failed','cleanup_conflict',
 'scan_unavailable','wireless_unavailable','unsupported_radio','channel_conflict','address_conflict'];
const STATES=['searching_wired','searching_wireless','waiting_retry','waiting_authorization','select_controller'];
const ERRORS=['internal_error','not_authorized','peer_unavailable','onboarding_failed','identity_error','clock_error',
 'invalid_invitation','invalid_code','invalid_identity','invalid_request','invalid_wireless',
 'invitation_expired','already_bound','already_registered','request_reused','limit_exceeded',
 'wired_not_allowed','mesh_disabled','busy','storage_error','runtime_unavailable','protocol_error',
 'timeout','network_unavailable','wireless_unavailable','scan_unavailable','unsupported','invalid_state','wired_no_address',
 'wireless_control_incompatible','wireless_probe_unavailable','missing_mesh','missing_mesh_acl','preflight_failed'];
export function enrollment_error(value) {
 return value==null ? null : index(ERRORS,value)>=0 ? value : 'internal_error';
}
function hex(value,n) { return type(value)=='string' && length(value)==n && match(value,/^[0-9a-f]+$/)!=null; }
function number(value,max) { return type(value)=='int' && value>=0 && value<=max; }
function owner_valid(v) {
 return type(v)=='object' && equal(sort(keys(v)),sort(['pid','start_ticks','run_id'])) &&
  number(v.pid,MAX) && v.pid>0 && type(v.start_ticks)=='string' &&
  match(v.start_ticks,/^[0-9]{1,20}$/)!=null && hex(v.run_id,32);
}
function address(value) {
 if(type(value)!='string')return false;
 let parts=split(value,'.');if(length(parts)!=4)return false;
 for(let p in parts)if(!match(p,/^[0-9]{1,3}$/) || int(p)>255 || length(p)>1 && substr(p,0,1)=='0')return false;
 return true;
}
export function enrollment_hints(candidates,points) {
 if(type(candidates)!='array' || type(points)!='array')die('runtime_unavailable: Invalid discovery observations');
 let wired=[],wireless=[];
 for(let c in slice(candidates,0,8)) {
  if(type(c)!='object' || !valid_text(c.name,1,64) || !hex(c.controller_id,32) ||
   !hex(c.network_id,32) || !hex(c.fingerprint,64) || !address(c.address) ||
   !match(c.interface || '',/^[a-zA-Z0-9_.-]{1,32}$/))continue;
  push(wired,{name:c.name,controller_id:c.controller_id,network_id:c.network_id,fingerprint:c.fingerprint,
   address:c.address,interface:c.interface,verified:false,binding_conflict:c.binding_conflict===true});
 }
 for(let p in slice(points,0,16)) {
  if(type(p)!='object' || !valid_text(p.ssid,1,32) ||
   !match(p.bssid || '',/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/) ||
   !match(p.device || '',/^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/) ||
   type(p.signal)!='int' || p.signal< -127 || p.signal>0 ||
   !number(p.channel,233) || p.channel<1)continue;
  push(wireless,{ssid:p.ssid,bssid:p.bssid,device:p.device,channel:p.channel,signal:p.signal,verified:false});
 }
 return {candidates:wired,access_points:wireless};
}
function valid(v) {
 if(type(v)!='object')return false;
 let actual=keys(v),extra=filter(actual,k=>index(FIELDS,k)<0),extended='transport' in v,
  handoff='handoff' in v,expected=[...(extended ? TRANSPORT_FIELDS : []),...(handoff ? HANDOFF_FIELDS : [])];
 if(!equal(sort(filter(actual,k=>index(FIELDS,k)>=0)),sort(FIELDS)) ||
  !equal(sort(extra),sort(expected)) || v.schema!=1 ||
  !match(v.boot || '',/^[0-9a-f-]{36}$/) || !hex(v.node_id,32) || !hex(v.identity_tag,64) ||
  !owner_valid(v.owner) || !number(v.revision,MAX) || !number(v.cycle,MAX) ||
  !number(v.observed_uptime_ms,1000000000000000) || !number(v.next_uptime_ms,1000000000000000) ||
  index(['wired','wireless'],v.phase)<0 || index(STATES,v.status)<0 ||
  v.error!=null && index(ERRORS,v.error)<0 ||
  type(v.candidates)!='array' || length(v.candidates)>8 ||
  type(v.access_points)!='array' || length(v.access_points)>16)return false;
 if(extended && (index(TRANSPORT,v.transport)<0 ||
  v.transport_error!=null && index(TRANSPORT_ERRORS,v.transport_error)<0 ||
  !number(v.transport_deadline,1000000000000000) ||
  (v.transport=='restoring' ? v.transport_deadline<=v.observed_uptime_ms ||
   v.transport_deadline>v.observed_uptime_ms+210000 : v.transport_deadline!=0)))return false;
 if(handoff && (index(HANDOFF_STATES,v.handoff)<0 || v.handoff_error!=null &&
  index(HANDOFF_ERRORS,v.handoff_error)<0))return false;
 let hints=enrollment_hints(v.candidates,v.access_points);
 return equal(hints.candidates,v.candidates) && equal(hints.access_points,v.access_points) &&
  (v.next_uptime_ms==0 || v.next_uptime_ms>=v.observed_uptime_ms &&
   v.next_uptime_ms<=v.observed_uptime_ms+30000);
}
function parse(raw) {
 if(raw==null)return null;
 if(type(raw)!='string' || !length(raw) || length(raw)>LIMIT)die('runtime_unavailable: Progress size is invalid');
 let v;try{v=json(raw);}catch(e){die('runtime_unavailable: Progress is corrupt');}
 if(!valid(v))die('runtime_unavailable: Progress structure is invalid');
 return v;
}
function current_age(progress,now) {
 return now>=progress.observed_uptime_ms &&
  (now-progress.observed_uptime_ms<=AGE || progress.transport=='restoring' &&
   progress.transport_deadline>now && progress.transport_deadline<=progress.observed_uptime_ms+210000);
}
export function enrollment_tag(io,key,identity,boot) {
 return io.hmac(key,sprintf('%J',canonical({domain:'mesh-manager/enrollment/progress/v1',boot,identity})));
}
function usable(identity) { return identity?.enrollment?.enabled===true &&
 (identity.role=='unbound' && !identity.binding && (!identity.joining || index(['requesting','pending'],identity.joining.status)>=0) ||
  identity.role=='ap' && type(identity.binding)=='object' && type(identity.handoff)=='object' && !identity.joining); }

/* The owner belongs to the long-lived worker, not a fresh service closure or an
 * RPC request. Raw identity objects remain independent; no durable overlay. */
export function enrollment_progress(io) {
 let token=null,lost=false,claimed=false;
 function current() {
  let disk=io.read(true);if(!disk?.key || !hex(disk.key,64))die('runtime_unavailable: Runtime key unavailable');
  return {key:disk.key,state:parse(disk.raw),storage:disk};
 }
 function begin(identity) {
  if(lost || !usable(identity))return null;
  let boot=io.boot(),now=io.now(),disk=current(),old=disk.state;
  if(!number(now,1000000000000000))die('runtime_unavailable: Invalid monotonic clock');
  if(!token)token={...io.owner(),run_id:io.random(16)};
  if(!owner_valid(token))die('runtime_unavailable: Invalid process owner');
  if(claimed && (!old || !equal(old.owner,token))) {lost=true;return null;}
  if(old && old.boot==boot && !equal(old.owner,token) && io.alive(old.owner.pid,old.owner.start_ticks)) {
   die('busy: Another enrollment worker owns discovery progress');
  }
  let tag=enrollment_tag(io,disk.key,identity,boot);
  if(!hex(tag,64))die('runtime_unavailable: Invalid private identity fence');
  let same=old && old.boot==boot && old.node_id==identity.id && old.identity_tag==tag && equal(old.owner,token) &&
   current_age(old,now);
  // A new owned observation generation must permanently reject old callbacks,
  // including revision-zero expiry and A->B->A identity restoration.
  if(claimed && old && !same)token={...token,run_id:io.random(16)};
  let retry=identity.enrollment?.retry,semantic=enrollment_error(identity.enrollment?.error);
  let deadline=semantic ? (retry?.boot==boot && number(retry.next,1000000000000000) ? max(now,min(now+30000,retry.next)) : now+30000) : 0;
  let progress=same ? old : {schema:1,boot,node_id:identity.id,identity_tag:tag,owner:clone(token),revision:0,
   observed_uptime_ms:now,phase:'wired',next_uptime_ms:deadline,cycle:0,status:semantic ? 'waiting_authorization' : 'searching_wired',error:semantic,candidates:[],access_points:[]};
  if(!same)io.publish(sprintf('%J',progress),disk.storage);
  claimed=true;
  return {storage:disk.storage,identity:clone(identity),boot,owner:clone(token),tag,progress:clone(progress)};
 }
 function check(frame) {
  if(lost || !claimed || !frame || !equal(token,frame.owner) || !equal(io.identity(),frame.identity) || io.boot()!=frame.boot || !usable(frame.identity))return false;
  let disk=current(),p=disk.state,now=io.now();
  if(!p || !equal(p.owner,frame.owner)) {lost=true;return false;}
  let ok=p.boot==frame.boot && p.node_id==frame.identity.id && p.identity_tag==frame.tag &&
   enrollment_tag(io,disk.key,frame.identity,frame.boot)==frame.tag && p.revision==frame.progress.revision &&
   current_age(p,now);
  if(ok)frame.storage=disk.storage;return ok;
 }
 function commit(frame,patch) {
  if(!check(frame))return false;
  if(type(patch)!='object' || length(filter(keys(patch),k=>index(PATCH,k)<0)))die('runtime_unavailable: Unknown progress field');
  let next=clone(frame.progress),now=io.now();
  for(let k,value in patch) {
   if(k=='next')next.next_uptime_ms=int(value*1000);
   else next[k]=k=='error' ? enrollment_error(value) : k=='handoff_error' ?
    value==null ? null : index(HANDOFF_ERRORS,value)>=0 ? value : 'internal_error' : clone(value);
  }
  if(patch.candidates!=null || patch.access_points!=null) {
   let hints=enrollment_hints(next.candidates,next.access_points);next.candidates=hints.candidates;next.access_points=hints.access_points;
  }
  if(equal(next,frame.progress))return true;
  if(next.revision>=MAX)die('runtime_unavailable: Progress revision limit reached');
  next.revision++;next.observed_uptime_ms=now;
  // Past rest deadlines need not be retained when a new action starts.
  if(next.next_uptime_ms && next.next_uptime_ms<now)next.next_uptime_ms=0;
  if(!valid(next))die('runtime_unavailable: Invalid progress patch');
  let text=sprintf('%J',next);if(length(text)>LIMIT)die('runtime_unavailable: Progress size limit reached');
  io.publish(text,frame.storage);frame.progress=next;return true;
 }
 return {begin,check,commit,lost:()=>lost};
}

/* Reader supplies only an independent captured raw identity and a read-only
 * storage adapter. Durable truth always has precedence over observations. */
export function project_enrollment(identity,boot,now,io) {
 let e=identity?.enrollment;if(!e)return null;
 let semantic=enrollment_error(e.error);
 let result={enabled:e.enabled===true,status:e.enabled===true ? semantic ? 'waiting_authorization' : 'searching_wired' : 'stopped',error:semantic,
  cycle:0,candidates:[],access_points:[],runtime_available:false,stale:false,runtime_error:null};
 let handoff=identity.role=='ap' && e.enabled===true && type(identity.handoff)=='object';
 if(identity.role=='ap') {
  result.error=null;result.status=e.enabled===true ? 'configuring' : 'joined';
  if(!handoff) {
   let job=identity.agent;
   if(e.enabled===true && job?.catchup===true && (job.retry_error || job.status=='error')) {
    result.status='configuration_blocked';result.error=enrollment_error(job.retry_error || job.error);
    result.retry_remaining=null;
   }
   if(e.enabled===true && job?.catchup===true && index(['rolled_back','expired','rollback_conflict'],job.status)>=0) {
    let counting=job.retry?.boot==boot && job.retry.next>now/1000;
    result.status=job.status=='rollback_conflict' || length(job.conflicts || []) ? 'recovery_conflict' :
     counting ? 'configuration_retry' : 'configuration_reconnect';
    result.retry_remaining=counting ? int(job.retry.next-now/1000+0.999) : null;
    if(job.retry_error && result.status!='recovery_conflict')result.status='configuration_blocked';
   }
   return result;
  }
 }
 if(e.enabled!==true){result.error=null;return result;}
 let joining=identity.joining;
 if(joining) {
  result.error=null;result.status=joining.status=='rejected' ? 'rejected' : 'pending';
  result.transport='unavailable';result.transport_error=null;
  if(joining.status=='rejected')return result;
 }
 if(identity.role!='unbound' && !handoff) {result.status='stopped';return result;}
 try {
  let disk=io.read(false),p=parse(disk?.raw);
  // Runtime progress can advance after the private identity capture. Its age
  // uses a same-source clock read after observation, while raw consent remains
  // bound to the original identity frame.
  now=io.now?.() ?? now;
  if(!number(now,1000000000000000) || !p || !disk.key || p.boot!=boot || p.node_id!=identity.id ||
   p.identity_tag!=enrollment_tag(io,disk.key,identity,boot) ||
   !current_age(p,now) || !io.alive(p.owner.pid,p.owner.start_ticks)) {
   result.stale=p!=null;result.runtime_error='runtime_unavailable';return result;
  }
  if(handoff) return {...result,runtime_available:true,handoff:p.handoff || 'configuring',
   error:p.handoff_error || null,retry_remaining:max(0,int((p.next_uptime_ms-now+999)/1000))};
  if(joining) return {...result,runtime_available:true,transport:p.transport || 'unavailable',
   transport_error:p.transport_error || null,transport_deadline:p.transport_deadline || 0,
   retry_remaining:max(0,int((p.next_uptime_ms-now+999)/1000))};
  return {...result,status:semantic ? 'waiting_authorization' : p.status,error:semantic || p.error,cycle:p.cycle,candidates:p.candidates,access_points:p.access_points,runtime_available:true};
 }catch(e){result.runtime_error='runtime_unavailable';return result;}
}
