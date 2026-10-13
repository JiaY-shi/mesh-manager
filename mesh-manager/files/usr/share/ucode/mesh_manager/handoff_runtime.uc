// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import * as durable from './durable.uc';
import { equal, clone } from './model.uc';
import { snapshot, first_handoff_locked, first_handoff_stage } from './runtime.uc';
import { onboard_capture, onboard_handoff_start, onboarding_transport,
 onboarding_owned_transport, onboard_stop_owned } from './onboarding.uc';
import { enrollment_uptime } from './enrollment_runtime.uc';
import { handoff_capture, handoff_state } from './first_handoff.uc';
import { handoff_client } from './first_handoff_client.uc';
import { exchange, handoff_exchange } from './peer_transport.uc';

const MATERIAL=['identity','key','join_ca','network_ca','cert'];
function conflict() { die('handoff_conflict: Original first configuration context changed'); }
function remaining(deadline, maximum) {
 let now=enrollment_uptime();
 if(type(deadline)!='int' || deadline<=now)die('handoff_timeout: Original handoff deadline expired');
 return min(maximum,deadline-now);
}
function material() {
 let observed=onboard_capture().scope, scope={};
 for(let k in MATERIAL)scope[k]=observed[k];
 return {native:observed,scope};
}
// This read has no network or write effects. Unknown temporary resources throw;
// an expired lease does not turn an existing actor into an absent one.
export function handoff_context() {
 let original=material(), identity=json(original.scope.identity);
 return {scope:original.scope,journal:durable.read('state.json'),
  snapshot:sprintf('%J',snapshot()),boot:original.native.boot,now:enrollment_uptime(),
  transport:onboarding_owned_transport(identity.binding?.address)};
}
function locked(callback) {
 // Existing writer lock order: cluster first, local transaction second.
 return durable.locked(()=>first_handoff_locked(callback),1);
}
export function handoff_poll_context() {
 return locked(()=>{
  let captured=handoff_context();
  if(handoff_state(captured.scope,captured.journal,captured.snapshot,captured.boot,captured.now).stage!='configuring')return null;
  return handoff_capture(captured.scope,captured.journal,captured.snapshot,captured.boot,captured.now,captured.transport);
 });
}
export function handoff_stage(intent,request_id,takeover,approval,frame,proof) {
 // node_command already owns the cluster lock. The runtime stage takes the
 // local lock and publishes the marker with its original single staged save.
 return first_handoff_stage(intent,request_id,takeover,approval,frame,proof,handoff_context);
}
function ifindex(device) {
 if(index(['mm-cw','mm-cm'],device)<0)conflict();
 let raw=trim(fs.readfile('/sys/class/net/'+device+'/ifindex') || '');
 if(!match(raw,/^[1-9][0-9]{0,9}$/) || +raw>2147483647)return null;
 return int(raw);
}
export function handoff_poll(binding,request,frame,record) {
 if(type(record)!='function')conflict();
 // Initial catchup is fetched over the original verified STA, never a LAN
 // fallback invented merely because managed control is not ready yet.
 let transport=onboarding_transport(binding.address);
 if(frame.transport==null || !equal(transport,frame.transport))
  die('handoff_unhealthy: Original temporary controller path is not verified');
 remaining(frame.deadline,16000);
 return exchange(binding,{...request,control_schema:1},false,transport.device,remaining(frame.deadline,16000),record);
}
function client_io(provider) {
 return {locked,capture:handoff_context,nonce:()=>durable.random(16),wall:()=>time(),
  restore_original:(cold,deadline)=>{
   remaining(deadline,210000);
   let observed=material(), extra={...observed.native,state:durable.read('state.json'),snapshot:sprintf('%J',snapshot())};
   if(!equal(observed.scope,cold.scope) || extra.state!==cold.journal || extra.snapshot!==cold.snapshot || extra.boot!==cold.boot)conflict();
   onboard_handoff_start({scope:extra},deadline,provider);
   let transport=onboarding_transport(json(cold.scope.identity).binding.address);
   if(transport==null || !equal(transport,onboarding_owned_transport(transport.controller)))conflict();
   remaining(deadline,1);
   return {restored:true,transport};
  },
  health:(frame,request,deadline)=>{
   let binding=json(frame.scope.identity).binding,last;
   for(let device in ['mm-cw','mm-cm']) {
    let index=ifindex(device);if(index==null)continue;
    let observed;
    try {
     handoff_exchange({...binding,address:'169.254.254.1'},request,device,
      remaining(deadline,16000),value=>{observed=value;});
    }catch(e){last=e;continue;}
    let now=enrollment_uptime();
    if(now>=deadline || durable.boot()!==frame.boot || ifindex(device)!==index || !equal(observed?.request,request))conflict();
    return {request:observed.request,reply:observed.reply,device,ifindex:index,boot:frame.boot,observed:now};
   }
   die(last?.message || 'handoff_unhealthy: Isolated managed controller path is unavailable');
  },
  cleanup:(owner,deadline)=>{
   remaining(deadline,12000);
   let original=onboarding_owned_transport(owner?.controller);
   if(!equal(original,owner))conflict();
   if(owner!=null && !onboard_stop_owned(owner))die('cleanup_conflict: Original temporary controller path could not be stopped');
   remaining(deadline,1);
   if(onboarding_owned_transport(owner?.controller)!=null)conflict();
   return owner==null ? {status:'absent',boot:durable.boot()} : {status:'stopped',boot:durable.boot(),owner:clone(owner)};
  },
  commit:(expected,identity,deadline)=>{
   let current=handoff_context();
   if(!equal(current.scope,expected.scope) || current.journal!==expected.journal || current.snapshot!==expected.snapshot ||
    current.boot!==expected.boot || current.now<expected.now || current.transport!=null)conflict();
   remaining(deadline,5000);
   durable.write_cas('identity.json',expected.scope.identity,identity,remaining(deadline,5000));
  }};
}
export function handoff_tick(progress,provider) {
 let identity=durable.load('identity.json');
 if(identity?.role!='ap' || identity.handoff==null || identity.enrollment?.enabled!==true)return false;
 let frame=progress.begin(identity);if(!frame)return false;
 let now=enrollment_uptime();
 if(frame.progress.next_uptime_ms>now)return true;
 const deadline=now+210000;
 if(!progress.commit(frame,{phase:'wireless',status:'waiting_authorization',handoff:'configuring',handoff_error:null,
  transport:'restoring',transport_error:null,transport_deadline:deadline}))return false;
 function rest(patch) {
  // An expired display frame must not remove the fixed rest after a late IO.
  // A new display frame still requires the exact original durable identity and
  // original worker ownership; it never renews any IO/approval deadline.
  let current=progress.check(frame) ? frame : progress.begin(identity);
  return current && progress.commit(current,{...patch,transport:'unavailable',transport_error:null,
   transport_deadline:0,next:enrollment_uptime()/1000+30});
 }
 let result;
 try {
  result=handoff_client(client_io(provider)).step(deadline);
  if(result.joined)return true;
  rest({handoff:result.stage,handoff_error:result.error});
 }catch(e){
  rest({handoff:'blocked',handoff_error:match(e.message || '',/^([a-z_]{1,32}):/)?.[1] || 'internal_error'});
 }
 return true;
}
