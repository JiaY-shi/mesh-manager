// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal } from './model.uc';
import { onboard_authority, onboard_frame_valid, onboard_witness, onboard_arm } from './onboard_session.uc';

export function onboard_worker(spec,io) {
 let actor=null,ready=false,seen=null,last=null,error='onboarding_failed';
 let initial={...spec.scope,raw_identity:spec.scope.identity,identity:json(spec.scope.identity),code:spec.code,mode:spec.mode,standby:spec.standby};
 function scope() {
  let raw=io.scope();if(raw?.error || type(raw.identity)!='string')die('runtime_unavailable: Onboarding identity unavailable');
  return {...raw,raw_identity:raw.identity,identity:json(raw.identity)};
 }
 function observe(allow_unavailable) {
  let current,fresh;
  try{current=scope();}catch(e){if(allow_unavailable && seen?.permit)return null;die(e.message);}
  let authority=onboard_authority(initial,current,seen,io.verify);
  if(!authority)die('identity_error: Onboarding authorization changed');
    let info=actor.info();if(info?.error)die(info.error+': Onboarding resource unavailable');
  let associated=io.association(spec.bssid);
  try{fresh=scope();}catch(e){if(allow_unavailable && seen?.permit)return null;die(e.message);}
  // An identity A->B->A in another callback cannot reuse this frame: each
  // invocation creates its own exact raw frame and actor publication CAS.
  if(!equal(current,fresh)) {
   authority=onboard_authority(initial,fresh,authority,io.verify);
   if(!authority)die('identity_error: Onboarding observation changed');
  }
  if(io.now()>=info.deadline)die('identity_error: Onboarding observation changed');
  seen=authority;
  let value={...info,authority:onboard_witness(initial,fresh,authority,io.verify),ssid:spec.ssid,controller:spec.controller || info.controller,connected:associated===true};
  if(!actor.publish(value,io.raw(fresh)))die('identity_error: Onboarding observation changed');
  return value;
 }
 try {
  let resume=spec.mode=='resume',handoff=spec.mode=='handoff',standby=spec.mode=='standby';
  if(standby ? !onboard_authority(initial,initial,null,io.verify) : handoff ? initial.identity?.role!='ap' || initial.identity?.joining ||
   io.verify.handoff_cold?.(spec.scope)!==true : initial.identity?.role!='unbound' || initial.identity?.binding ||
   (resume ? initial.identity.enrollment?.enabled!==true ||
    index(['requesting','pending'],initial.identity.joining?.status)<0 : initial.identity.joining))
   die('identity_error: Onboarding requires an unbound device');
  let raw=io.scope(),core=clone(spec.scope);delete core.state;delete core.snapshot;delete core.cluster;
  if(!onboard_frame_valid({scope:core,started:spec.started,deadline:spec.started+60000},raw,io.now()))
   die('identity_error: Onboarding start approval changed');
  if('state' in spec.scope)raw={...raw,state:spec.scope.state,snapshot:spec.scope.snapshot};
  actor=io.begin(spec,raw);let info=actor?.info?.();if(info?.error || !info)die('onboarding_failed: Temporary station unavailable');
  let authority=onboard_authority(initial,{...raw,raw_identity:raw.identity,identity:json(raw.identity)},null,io.verify);
  if(!authority)die('identity_error: Onboarding original authority is unavailable');
  if(!actor.publish({...info,authority:onboard_witness(initial,initial,authority,io.verify),ssid:spec.ssid,controller:spec.controller || info.controller,connected:false},raw))die('identity_error: Onboarding start changed');
  let lease=actor.dhcp(raw);if(lease?.error)die(lease.error+': Temporary DHCP unavailable');
  last=observe();if(!last.connected || io.now()>=spec.started+60000)die('onboarding_failed: Actual association is unavailable');
  io.ready({active:true,connected:true,generation:last.generation,...(spec.mode=='discover' ? {controller:last.controller} : {}),ssid:spec.ssid,remaining:int((last.deadline-io.now())/1000)});ready=true;
  while(io.now()<last.deadline) {
   let event=actor.wait(3000);
   if(event===true)break;
   if(type(event)=='object') {
    let current=scope(),info=actor.info(),armed=onboard_arm(initial,current,seen,info,event,io.verify);
    if(armed) {
     seen=armed;last=observe();actor.permit_reply(last.connected===true);continue;
    }
    actor.permit_reply(false);
   }
   let observed=observe(true);if(observed)last=observed;
  }
 }catch(e) {
  let code=match(''+e,/([a-z_]+):/)?.[1];
  if(index(['identity_error','runtime_unavailable','cleanup_conflict','onboarding_failed','address_conflict'],code)>=0)error=code;
 }
 let closed=type(actor?.close)=='function' ? actor.close() : true;
 if(closed!==true)error='cleanup_conflict';
 if(!ready)io.ready({error});
 return closed===true;
}
