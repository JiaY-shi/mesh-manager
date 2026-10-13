// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as crypto from 'mesh_crypto';
import { clone, equal, valid_text } from './model.uc';
import { unseal } from './signed_response.uc';
import { approval_prepare } from './joining_exchange.uc';

import { hex, integer, hash, raw, object, exact, sign, sealed, journal, pristine, base_journal, scope_valid, authority, reference_prepare } from './handoff_reference.uc';

const ATTEMPT=50000, FRESH=30000;
const LINEAGE=['schema','origin','root_version','root_id','transaction','command','active','before_base','before_snapshot','after_snapshot','proof'];
const OWNER=['device','controller','generation','boot','pid','start_ticks','ifindex','phy','mac','scope_tag'];
function seconds(v){return (type(v)=='int' || type(v)=='double') && v>0 && v<1000000000000;}
function clock(boot,now){return type(boot)=='string' && length(boot)>0 && length(boot)<=64 && integer(now,0,1000000000000000);}
function owned(value,boot,address){return value==null || exact(value,OWNER) && value.device=='mm-onboard' && value.controller===address &&
 value.boot===boot && hex(value.generation,32) && hex(value.scope_tag,64) && integer(value.pid,1,2147483647) && integer(value.ifindex,1,2147483647) &&
 integer(value.phy,0,1023) && type(value.start_ticks)=='string' && match(value.start_ticks,/^[0-9]{1,20}$/)!=null &&
 type(value.mac)=='string' && match(value.mac,/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/)!=null;}

// The exact result is the single original final AP save/permit target.
export function handoff_prepare(before,approved,journal_raw,snapshot_raw,checkpoint){
 let permitted=approval_prepare({...before,state:journal_raw,snapshot:snapshot_raw},checkpoint);
 if(!permitted || permitted.expected_identity!==approved.identity || permitted.cert!==approved.cert)
  die('handoff_conflict: Original joining approval checkpoint is unavailable');
 if(checkpoint.handoff!=null)return {identity:approved.identity,ref:clone(checkpoint.handoff)};
 return reference_prepare(before,approved,journal_raw,snapshot_raw);
}
function command(scope,request,reply,wall){
 let data=scope_valid(scope);
 if(request?.protocol!==1 || request.action!='poll' || request.network_id!=data.binding.network_id || !hex(request.nonce,32) || reply?.signed==null)
  die('handoff_conflict: First configuration requires a nonce-bound signed Root poll');
 let result=unseal(data.binding,request,reply,{read:name=>name=='network-ca.crt'?scope.network_ca:name=='device.crt'?scope.cert:null,time:()=>wall}),c=result.command;
 if(result.controller_id!=data.binding.controller_id || result.network_id!=data.binding.network_id || c?.action!='catchup' ||
  !valid_text(c.id,16,96,true) || !integer(c.version,1,2147483647) || type(c.intent)!='object' || c.transaction!=null && !valid_text(c.transaction,16,96,true))
  die('handoff_conflict: Only original signed first catchup may claim handoff');
 return c;
}
function static_active(active){let v=clone(active);delete v.status;delete v.deadline;delete v.failure;delete v.conflicts;return hash(raw(v));}
function expected_snapshot(active){
 let s=clone(active.snapshot);
 for(let op in active.ops){
  if(type(op)!='object' || index(['network','wireless','dhcp','firewall','usteer'],op.config)<0 || !crypto.identifier(op.section) ||
   type(op.type)!='string' || op.option!=null && !crypto.identifier(op.option))die('handoff_conflict: Invalid first transaction ownership');
  let section=s[op.config]?.[op.section];
  if(op.option==null){
   if(!equal(section ?? null,op.before ?? null) || op.after!=null && (op.after.type!==op.type || type(op.after.values)!='object'))die('handoff_conflict: Invalid first section baseline');
   if(op.after==null)delete s[op.config]?.[op.section];else{if(!s[op.config])s[op.config]={};s[op.config][op.section]=clone(op.after);}
  }else{
   if(section?.type!==op.type || !equal(section.values?.[op.option] ?? null,op.before ?? null))die('handoff_conflict: Invalid first option baseline');
   if(op.after==null)delete section.values[op.option];else section.values[op.option]=clone(op.after);
  }
 }
 return hash(raw(s));
}

// The caller's real compiler/stage save adapter must publish this seal together
// with its first staged journal, not as an after-stage identity update.
export function handoff_stamp(scope,before_raw,staged_raw,snapshot_raw,request,reply,compiled,wall){
 let a=authority(scope),before=journal(before_raw),staged=object(staged_raw),tx=staged.active,c=command(scope,request,reply,wall);
 if(!pristine(before) || hash(before_raw)!==a.ref.journal || hash(snapshot_raw)!==a.ref.snapshot ||
  hash(base_journal(staged))!==a.ref.journal_base || staged.schema!==1 || staged.version!==0 || staged.paused!==false || staged.first_handoff!=null ||
  !exact(tx,['id','request_id','intent','kind','mesh_enabled','status','ops','snapshot','boot','created','deadline','conflicts']) ||
  tx.kind!='configure' || tx.mesh_enabled!=null || tx.status!='staged' || tx.deadline!=null ||
  !valid_text(tx.id,1,96,true) || tx.request_id!='mesh-'+(c.transaction || c.id) || !equal(tx.intent,compiled) ||
  !equal(tx.snapshot,object(snapshot_raw)) || type(tx.ops)!='array' || type(tx.conflicts)!='array' || length(tx.conflicts) || tx.failure!=null)
  die('handoff_conflict: First staged transaction does not match original approval');
 let ref={schema:1,origin:a.ref.proof,root_version:c.version,root_id:c.id,transaction:c.transaction || c.id,command:hash(raw(c)),
  active:static_active(tx),before_base:a.ref.journal_base,before_snapshot:a.ref.snapshot,after_snapshot:expected_snapshot(tx)};
 ref.proof=sign(ref,scope.key,'journal');staged.first_handoff=ref;
 return raw(staged);
}
function agent_valid(data,mark,status){
 let job=data.agent;if(job==null)return data.cluster_version==null || data.cluster_version===0;
 let allowed=['id','transaction','version','mode','status','transaction_id','catchup','conflicts','error','health_confirmed'];
 if(type(job)!='object' || length(filter(keys(job),k=>index(allowed,k)<0)) || job.id!==mark.root_id || job.transaction!==mark.transaction || job.version!==mark.root_version ||
  job.transaction_id!==status.id || job.catchup!==true || job.mode!==status.intent?.backhaul?.mode ||
  index(['staged','apply_requested','applying','awaiting_confirm','committed'],job.status)<0 || job.error!=null ||
  job.conflicts!=null && (type(job.conflicts)!='array' || length(job.conflicts)) ||
  job.health_confirmed!=null && job.health_confirmed!==true || data.cluster_version!=null && data.cluster_version!==0 && data.cluster_version!==mark.root_version)
  return false;
 return status.status=='committed' || (job.status!='committed' && job.health_confirmed!==true && (data.cluster_version==null || data.cluster_version===0));
}
function inspect(scope,journal_raw,snapshot_raw,boot,now,transport_only){
 if(!clock(boot,now))die('handoff_conflict: Initial handoff clock is invalid');
 let a=authority(scope),j=journal(journal_raw),tx=j.active,mark=j.first_handoff;
 if(j.paused!==false || j.restore_checkpoint!=null)die('handoff_paused: Deliberate pause or restoration blocks initial handoff');
 if(mark==null){
  if(!pristine(j) || hash(journal_raw)!==a.ref.journal || !transport_only && hash(snapshot_raw)!==a.ref.snapshot || a.data.agent!=null ||
   a.data.cluster_version!=null && a.data.cluster_version!==0)die('handoff_conflict: Initial journal lineage is unavailable');
  return {stage:'configuring',restore:true,retain:true,...a,j};
 }
 if(!sealed(mark,scope.key,'journal',LINEAGE) || mark.schema!==1 || mark.origin!==a.ref.proof || !integer(mark.root_version,1,2147483647) ||
  !valid_text(mark.root_id,16,96,true) || !valid_text(mark.transaction,16,96,true) ||
  length(filter(['origin','command','active','before_base','before_snapshot','after_snapshot'],k=>!hex(mark[k],64))) || mark.before_base!==a.ref.journal_base ||
  mark.before_snapshot!==a.ref.snapshot || hash(base_journal(j))!==mark.before_base ||
  tx?.kind!='configure' || tx.mesh_enabled!=null || static_active(tx)!==mark.active || !agent_valid(a.data,mark,tx) ||
  type(tx.conflicts)!='array' || length(tx.conflicts) || tx.failure!=null || tx.request_id!='mesh-'+mark.transaction)
  die('handoff_conflict: First transaction lineage changed');
 if(index(['rolled_back','expired','rollback_conflict','rollback_requested','rolling_back'],tx.status)>=0)
  die('handoff_conflict: Failed first transaction requires existing rollback and manual review');
 if(tx.status=='applying'){
  if(transport_only===true && tx.boot===boot && seconds(tx.deadline) && tx.deadline*1000>now &&
   j.version===0 && j.intent==null && j.saved_intent==null && type(j.owned)=='array' && !length(j.owned) && type(j.history)=='array' && !length(j.history))
   return {stage:'applying',restore:false,retain:true,...a,j,mark};
  die('handoff_recovery: Interrupted application belongs to independent transaction rollback');
 }
 if(index(['staged','apply_requested','awaiting_confirm','committed'],tx.status)<0)die('handoff_conflict: Unknown first transaction phase');
 if(tx.status!='committed' && (tx.boot!==boot || tx.status=='awaiting_confirm' && (!seconds(tx.deadline) || tx.deadline*1000<=now)))
  die('handoff_recovery: Previous-boot or expired first transaction belongs to recovery');
 if(tx.status=='committed'){
  if(j.version!==1 || !equal(j.intent,tx.intent) || !equal(j.saved_intent,tx.intent) || !equal(j.owned,tx.ops) || type(j.history)!='array' || length(j.history)!=1 ||
   j.history[0].id!==tx.id || j.history[0].request_id!==tx.request_id || j.history[0].status!='committed' || j.history[0].kind!='configure' ||
   j.history[0].version!==1 || j.history[0].failure!=null || type(j.history[0].conflicts)!='array' || length(j.history[0].conflicts))
   die('handoff_conflict: Genuine first commit journal is unavailable');
 }else if(j.version!==0 || j.intent!=null || j.saved_intent!=null || type(j.owned)!='array' || length(j.owned) || type(j.history)!='array' || length(j.history))
  die('handoff_conflict: Previously managed journal cannot become initial handoff');
 let expected=tx.status=='staged' || tx.status=='apply_requested'?mark.before_snapshot:mark.after_snapshot;
 if(transport_only!==true && hash(snapshot_raw)!==expected)die('handoff_conflict: External configuration is preserved');
 return {stage:tx.status=='committed'?'committed':tx.status=='awaiting_confirm'?'awaiting_health':'staged',restore:false,retain:true,...a,j,mark};
}
// Private retention check for an already-permitted warm owner only. It grants
// no cold startup, UCI write, health completion or cleanup authority.
export function handoff_transport_valid(scope,journal_raw,boot,now,permitted_ref){
 try{
  if(permitted_ref==null || !equal(object(scope?.identity).handoff,permitted_ref))return false;
  inspect(scope,journal_raw,null,boot,now,true);return true;
 }catch(e){return false;}
}
export function handoff_state(scope,journal_raw,snapshot_raw,boot,now){
 try{let s=inspect(scope,journal_raw,snapshot_raw,boot,now);return {stage:s.stage,restore:s.restore,retain:s.retain,error:null};}
 catch(e){return {stage:'blocked',restore:false,retain:true,error:match(e.message || '',/^(handoff_[a-z]+):/)?.[1] || 'handoff_conflict'};}
}
export function handoff_capture(scope,journal_raw,snapshot_raw,boot,now,transport,outer){
 inspect(scope,journal_raw,snapshot_raw,boot,now);
 if(!owned(transport,boot,json(scope.identity).binding.address) || outer!=null && !integer(outer,0,1000000000000000))
  die('handoff_conflict: Initial handoff clock is invalid');
 let deadline=outer==null?now+ATTEMPT:min(now+ATTEMPT,outer);
 if(deadline<=now)die('handoff_conflict: Initial handoff deadline expired');
 return {scope:clone(scope),journal:journal_raw,snapshot:snapshot_raw,boot,started:now,deadline,transport:clone(transport)};
}
export function handoff_check(frame,scope,journal_raw,snapshot_raw,boot,now,transport){
 return type(frame)=='object' && frame.boot===boot && clock(boot,now) && integer(frame.started,0,1000000000000000) &&
  integer(frame.deadline,frame.started+1,frame.started+ATTEMPT) && now>=frame.started && now<frame.deadline &&
  equal(frame.scope,scope) && frame.journal===journal_raw && frame.snapshot===snapshot_raw && equal(frame.transport,transport);
}
export function handoff_request(frame,nonce){
 if(!hex(nonce,32) || !handoff_check(frame,frame?.scope,frame?.journal,frame?.snapshot,frame?.boot,frame?.started,frame?.transport))
  die('handoff_unhealthy: First managed receipt capture or nonce is invalid');
 let s=inspect(frame.scope,frame.journal,frame.snapshot,frame.boot,frame.started);
 if(s.stage!='committed')die('handoff_unhealthy: First configuration is not committed');
 return {protocol:1,network_id:s.data.binding.network_id,action:'handoff_check',nonce,
  request_id:s.ref.request,version:s.mark.root_version,transaction_id:s.j.active.id};
}
function health(frame,proof,wall){
 let s=inspect(frame.scope,frame.journal,frame.snapshot,frame.boot,frame.started),data=s.data,request=proof?.request;
 if(!exact(request,['protocol','network_id','action','nonce','request_id','version','transaction_id']) || request.protocol!==1 ||
  request.network_id!==data.binding.network_id || request.action!='handoff_check' || !hex(request.nonce,32) || request.request_id!==s.ref.request ||
  request.version!==s.mark?.root_version || request.transaction_id!==s.j.active?.id || proof?.reply?.signed==null)
  die('handoff_unhealthy: First managed nonce-bound receipt request is invalid');
 let result=unseal(data.binding,request,proof.reply,{read:name=>name=='network-ca.crt'?frame.scope.network_ca:name=='device.crt'?frame.scope.cert:null,time:()=>wall}),receipt=result.receipt,
  fingerprint=crypto.fingerprint(frame.scope.cert);
 if(s.stage!='committed' || type(proof)!='object' || index(['mm-cw','mm-cm'],proof.device)<0 || proof.boot!==frame.boot ||
  !integer(proof.ifindex,1,2147483647) || !integer(proof.observed,frame.started,frame.deadline-1) ||
  result.controller_id!==data.binding.controller_id || result.network_id!==data.binding.network_id ||
  !exact(receipt,['schema','status','request_id','node_id','root_id','root_version','transaction_id','local_version','certificate']) ||
  receipt.schema!==1 || receipt.status!='committed' || receipt.request_id!==s.ref.request || receipt.node_id!==data.id ||
  receipt.root_id!==s.mark.root_id || receipt.root_version!==s.mark.root_version || receipt.transaction_id!==s.j.active.id ||
  receipt.local_version!==1 || !hex(fingerprint,64) || receipt.certificate!==fingerprint)
  die('handoff_unhealthy: First managed control health was not proven');
 return s;
}
export function handoff_completion(frame,scope,journal_raw,snapshot_raw,boot,now,transport,proof,wall){
 if(!handoff_check(frame,scope,journal_raw,snapshot_raw,boot,now,transport))die('handoff_conflict: Initial handoff completion scope changed');
 let s=health(frame,proof,wall);
 if(proof.observed>now || now-proof.observed>FRESH)die('handoff_unhealthy: Managed control observation is stale');
 let data=clone(s.data);delete data.handoff;
 data.enrollment={...data.enrollment,enabled:false,status:'joined',error:null,code:null,password:null,ssid:null};
 if(data.agent){data.agent.status='committed';data.agent.health_confirmed=true;}
 data.cluster_version=s.mark.root_version;
 return {frame:clone(frame),identity:raw(data),cleanup:clone(frame.transport),proof:clone(proof)};
}
export function handoff_finish(plan,scope,journal_raw,snapshot_raw,boot,now,transport,receipt,wall){
 let f=plan?.frame;
 if(!handoff_check(f,scope,journal_raw,snapshot_raw,boot,now,f?.transport) || transport!=null ||
  receipt?.boot!==boot || (f.transport==null ? receipt.status!='absent' : receipt.status!='stopped' || !equal(receipt.owner,f.transport)))
  die('handoff_conflict: Original owned cleanup or completion scope is unproved');
 health(f,plan.proof,wall);
 if(plan.proof.observed>now || now-plan.proof.observed>FRESH || now+5000>=f.deadline)
  die('handoff_unhealthy: Completion cannot cover the remaining durable write budget');
 let expected=handoff_completion(f,scope,journal_raw,snapshot_raw,boot,now,f.transport,plan.proof,wall);
 if(plan.identity!==expected.identity || !equal(plan.cleanup,f.transport))die('handoff_conflict: Completion plan changed');
 return plan.identity;
}
