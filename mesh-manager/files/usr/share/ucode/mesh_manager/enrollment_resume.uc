// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal, valid_text } from './model.uc';
import { onboard_authority } from './onboard_session.uc';

const ATTEMPT=210000,REST=30000,CLEANUP=12000;
const NETWORK_ERRORS=['peer_unavailable','network_unavailable','timeout','onboarding_failed'];
const PUBLIC_ERRORS=['requires_credentials','target_changed','identity_error','runtime_unavailable',
 'peer_unavailable','network_unavailable','timeout','onboarding_failed','cleanup_conflict',
 'scan_unavailable','wireless_unavailable','unsupported_radio','channel_conflict','address_conflict'];
function hex(value,n) {return type(value)=='string' && length(value)==n && match(value,/^[0-9a-f]+$/)!=null;}
function scope_identity(scope) {
 if(type(scope)!='object' || scope.error || type(scope.identity)!='string')return null;
 try{return json(scope.identity);}catch(e){return null;}
}
export function resume_candidate(identity) {
 return identity?.role=='unbound' && !identity.binding && identity.enrollment?.enabled===true &&
  index(['requesting','pending'],identity.joining?.status)>=0;
}
export function resume_credentials(identity) {
 let e=identity?.enrollment;
 return e?.enabled===true && hex(e.epoch,32) && valid_text(e.ssid,1,32) &&
  type(e.password)=='string' && length(e.password)>=8 && length(e.password)<=63 && type(e.code)=='string';
}
/* Original durable request is authority after its invitation has expired.
 * This function neither generates a request nor consults expiry/discovery. */
export function resume_capture(scope,decode,verify) {
 let identity=scope_identity(scope),j=identity?.joining;
 if(!resume_candidate(identity))return {error:'requires_credentials'};
 if(!resume_credentials(identity))return {error:'requires_credentials'};
 if(!hex(identity.id,32) || !hex(j.request_id,32) || !hex(j.secret,64) ||
  type(scope.key)!='string' || !length(scope.key) || type(scope.boot)!='string' || !hex(scope.tag,64))
  return {error:'identity_error'};
 if(type(verify.key)=='function') {
  let fingerprint=verify.key(scope.key);
  if(!fingerprint || fingerprint!==identity.fingerprint || substr(fingerprint,0,32)!==identity.id)return {error:'identity_error'};
 }
 let code;try{code=decode(identity.enrollment.code);}catch(e){return {error:'target_changed'};}
 let invitation=j.invitation;
 if(type(invitation)!='object' || invitation.protocol!=1 || invitation.address!=code.address ||
  invitation.fingerprint!=code.fingerprint || invitation.token!=code.token || invitation.port!=37901 ||
  invitation.enroll_port!=37902 || !hex(invitation.controller_id,32) || !hex(invitation.network_id,32) ||
  invitation.controller_id==identity.id || type(invitation.ca)!='string' || length(invitation.ca)>4096 ||
  scope.join_ca!=invitation.ca || !verify.ca(invitation.ca,code.fingerprint))return {error:'target_changed'};
 let initial={...clone(scope),identity:clone(identity),code:clone(code),mode:'resume'};
 let seen=onboard_authority(initial,initial,null,verify);
 if(!seen)return {error:'identity_error'};
 return {scope:clone(scope),identity:clone(identity),code:clone(code),initial,seen};
}
export function resume_unchanged(capture,current,now,deadline) {
 return !capture?.error && equal(capture.scope,current) && type(now)=='int' && now>=0 && now<deadline;
}
export function resume_continues(capture,current,verify) {
 let identity=scope_identity(current);
 return identity && onboard_authority(capture.initial,{...current,identity},capture.seen,verify)!=null;
}
function error_code(error) {
 let value=match(error?.message || ''+error,/^([a-z_]{1,32}):/)?.[1];
 return index(PUBLIC_ERRORS,value)>=0 ? value : 'runtime_unavailable';
}
/* One captured automatic request, one retry deadline, and at most one owned
 * STA. Networking and the original pairing commit are injected by advanced;
 * no write/lock helper, pairing join() or invitation generator lives here. */
export function enrollment_resume_service(io) {
 function tick(identity) {
  if(!resume_candidate(identity))return false;
  let frame=io.progress.begin(identity);if(!frame)return false;
  let now=io.now();if(now<frame.progress.next_uptime_ms)return true;
  let deadline=now+ATTEMPT,handle=null,capture=null;
  function update(patch) {return io.progress.commit(frame,patch);}
  function changed() {return !io.progress.check(frame) || (capture &&
   !resume_unchanged(capture,io.scope(),io.now(),deadline-CLEANUP));}
  function rest(error,transport) {
   return update({transport:transport || 'unavailable',transport_error:error,
    transport_deadline:0,next:(io.now()+REST)/1000});
  }
  function cleanup() {
   if(!handle)return true;
   let value=io.cleanup_owned(handle);handle=null;return value===true;
  }
  function continues() {
   return type(io.resume_continues)=='function' ? io.resume_continues(capture,handle)===true :
    resume_continues(capture,io.scope(),io.verify);
  }
  function poll() {
   if(io.now()>=deadline-CLEANUP || !io.progress.check(frame))return false;
   let result=io.resume_poll(frame,deadline-CLEANUP);
   return result===true && io.now()<deadline-CLEANUP;
  }
  if(!update({transport:'restoring',transport_error:null,transport_deadline:deadline,next:0}))return false;
  // Try the actual same pinned request over an existing verified path first.
  // Missing Wi-Fi credentials must not prevent a safe existing wired poll.
  try {
   if(poll()) {
    if(io.progress.check(frame))update({transport:'verified',transport_error:null,transport_deadline:0,next:(io.now()+REST)/1000});
    return true;
   }
  }catch(e) {
   let code=error_code(e);
   if(index(NETWORK_ERRORS,code)<0){rest(code);return false;}
  }
  if(!io.progress.check(frame))return false;
  if(io.now()>=deadline-CLEANUP){rest('timeout');return false;}
  capture=resume_capture(io.scope(),io.decode,io.verify);
  if(capture.error){rest(capture.error,capture.error=='requires_credentials' ? 'requires_credentials' : null);return false;}
  if(!equal(capture.identity,identity) || changed())return false;
  try {
   handle=io.resume_start(capture,deadline-CLEANUP);
   if(!handle || handle.connected!==true || !hex(handle.generation,32))die('onboarding_failed: Temporary transport was not verified');
   if(io.now()>=deadline-CLEANUP)die('timeout: Pending request recovery exhausted its original budget');
   if(changed()) {
    if(!continues())cleanup();
    return false;
   }
   if(!update({transport:'verified',transport_error:null,transport_deadline:0,next:(io.now()+REST)/1000})) {
    if(!continues())cleanup();
    return false;
   }
   if(!poll())die('peer_unavailable: Original request was unavailable');
   // Approval/status publication may legitimately change durable identity.
   // Only the exact original Root/key/consent transition retains this STA.
   if(!continues())cleanup();
   return true;
  }catch(e) {
   let code=error_code(e);
   if(!cleanup())code='cleanup_conflict';
   rest(code);return false;
  }
 }
 return {tick};
}
