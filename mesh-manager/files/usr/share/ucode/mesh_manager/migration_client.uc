// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as crypto from 'mesh_crypto';
import { clone, equal } from './model.uc';
import { require_lease } from './control_lease.uc';
import { require_anchor } from './authority.uc';
import { migration_id, migration_hash, migration_binding, validate_transfer, validate_chunk, migration_receipt } from './migration_model.uc';
import { migration_budget as native_budget } from './migration_budget.uc';

const TERMINAL=['committed','rolled_back','rollback_conflict','expired'];
export function migration_client(io) {
const durable=io.durable,agent_local=io.local,exchange=io.exchange,migration_budget=io.budget || native_budget;
const effective_settings=io.effective_settings,local_intent=io.local_intent,mesh_mac=io.mesh_mac;
let resource_wait;
function replace(raw,data) {
 let text=sprintf('%J',data);
 if(length(text)>240000)die('migration_limit: Pending migration exceeds its private identity bound');
 durable.write_cas('identity.json',raw,text,5000);
}
function validate_source(data,command) {
 let m=data.migration;
 if(data.role!='ap' || !data.binding || !migration_id(command.transaction) ||
  command.source!=data.binding.controller_id || command.network_id!=data.binding.network_id ||
  type(command.epoch)!='int' || command.epoch!=(data.authority_epoch || 1)+1 ||
  !migration_binding(command.binding) || command.binding.epoch!=command.epoch ||
  command.binding.network_id!=data.binding.network_id || command.binding.controller_id!=command.target ||
  !migration_id(command.target) || command.target==command.source ||
  !migration_id(command.source) || !migration_hash(command.token) ||
  m && m.id!=command.transaction && index(['complete','cancelled','expired'],m.phase)<0)
  die('migration_conflict: Controller migration does not match the original binding');
 require_anchor(command.anchor);
 if(data.anchor==null && (command.anchor.id!=data.binding.controller_id || command.anchor.address!=data.binding.address))
  die('migration_conflict: The original controller must remain the data gateway');
 if(data.anchor!=null && !equal(data.anchor,command.anchor))
  die('migration_conflict: Controller migration cannot change the data gateway');
 return m?.id==command.transaction ? m : null;
}
function ready_transfer(data,m) {
 if(!m.chunks || length(m.chunks)!=m.total)die('migration_conflict: Authority transfer is incomplete');
 let raw=join('',m.chunks);
 if(crypto.sha256(raw)!=m.hash)die('migration_conflict: Transferred authority digest changed');
 let payload;
 try{payload=json(raw);}catch(e){die('migration_conflict: Transferred authority is invalid');}
 payload=validate_transfer(payload,m,data,durable.read('network-ca.crt'),crypto.fingerprint);
 let proof=crypto.sign(payload.ca_key,payload.ca_crt,crypto.csr(durable.read('device.key'),data.id),data.id);
 if(!proof || !crypto.verify_leaf(payload.ca_crt,proof,durable.read('device.key'),data.id))
  die('migration_conflict: Transferred CA signing key does not match the existing trust');
 return payload;
}
function promote(raw,data,m) {
 let payload=ready_transfer(data,m),local=durable.load('state.json');
 migration_budget(length(sprintf('%J',payload)));
 if(local?.active?.id!=m.transaction_id || local.active.status!='committed' ||
  !equal(local.intent,m.intent) || local.paused===true || m.fenced!==true)
  die('migration_conflict: Controller promotion requires the exact committed candidate and source fence');
 if(m.phase!='promoting'){m.phase='promoting';replace(raw,data);raw=durable.read('identity.json');}
 let key=durable.read('network-ca.key');
 if(key!=null && key!=payload.ca_key)die('storage_conflict: Target signing key changed outside the migration');
 if(key==null)durable.write_cas('network-ca.key',null,payload.ca_key,5000);
 let before=durable.read('cluster.json'),text=sprintf('%J',payload.cluster);
 if(before!=text && crypto.sha256(before || 'absent')!=m.cluster_before)
  die('storage_conflict: Target controller state changed outside the migration');
 if(before!=text)durable.write_cas('cluster.json',before,text,5000);
 // Publish authority last. A crash before this remains an AP which can only
 // resume this same fenced transfer; no independent Root initialization.
 data.role='root';data.network_id=payload.network_id;data.address=m.binding.address;
 data.control_address=m.binding.control_address;data.authority_epoch=m.epoch;
	data.control=clone(m.intent.control || null);
	data.ca_fingerprint=m.binding.ca_fingerprint;
 data.gateway=data.id==m.anchor.id ? m.anchor.gateway : 'bridge';data.anchor=clone(m.anchor);
 data.overrides=clone(m.settings);data.binding=null;delete data.agent;delete data.migration;
 replace(raw,data);
}
function local_progress(raw,data,m,local) {
	if(m.phase=='finishing'){finish_progress(raw,data,m,local);return;}
 if(m.phase=='cancelling') {
  let id=m.cancel_transaction_id || m.transaction_id;
  if(!id){m.phase='cancelled';replace(raw,data);return;}
  let active=local.active;
  if(active?.id!=id)die('migration_conflict: Migration recovery journal changed');
  if(m.cancel_transaction_id && index(['rolled_back','expired'],active.status)>=0) {
   if((m.cancel_attempts || 0)>=3)
    die('migration_conflict: AP cancellation recovered repeatedly; review its recovery journal');
   let local_agent=agent_local(),plan=local_agent.migration_preview(m.before_intent);
   if(length(plan.errors))die('ownership_conflict: Migration cancellation cannot overwrite external changes');
   let attempt=(m.cancel_attempts || 0)+1,
    stage=local_agent.migration_stage(m.before_intent,'migration-cancel-'+m.id+'-'+attempt,true,plan);
   m.cancel_attempts=attempt;m.cancel_transaction_id=stage.id;replace(raw,data);local_agent.apply(stage.id);return;
  }
  if(m.cancel_transaction_id && active.status=='staged') {
   agent_local().apply(id);return;
  }
  if(m.cancel_transaction_id && active.status=='awaiting_confirm' && local.health?.ok) {
   agent_local().confirm(id);m.phase='cancelled';replace(raw,data);return;
  }
  if(!m.cancel_transaction_id && index(['rolled_back','expired'],active.status)>=0 ||
   m.cancel_transaction_id && active.status=='committed') {
   m.phase='cancelled';replace(raw,data);return;
  }
  if(active.status=='rollback_conflict')die('ownership_conflict: Migration recovery preserved external changes');
  return;
 }
 if(!m.transaction_id || index(['applying','awaiting_confirm'],m.phase)<0)return;
 if(local.active?.id!=m.transaction_id)die('migration_conflict: Migration configuration journal changed');
 let phase=local.active.status;
 // Resume the same staged candidate after contention without renewing its deadline.
 if(phase=='staged'){agent_local().apply(m.transaction_id);return;}
 if(index(['awaiting_confirm','committed'],phase)>=0 && m.phase!=phase) {
  m.phase=phase;if(phase=='committed')m.metadata_committed=true;replace(raw,data);
 } else if(index(['rolled_back','rollback_conflict','expired'],phase)>=0) {
  m.phase='error';m.error=phase;replace(raw,data);
 }
}
function finish_progress(raw,data,m,state) {
 let local=agent_local();
 if(data.id==m.source && data.id!=m.anchor.id) {
  if(!m.final_transaction_id) {
   if((m.final_attempts || 0)>=3)die('migration_conflict: Listener retirement recovered repeatedly; resume migration to review again');
   migration_budget(0);
   if(state.active && index(['committed','rolled_back','expired'],state.active.status)<0 || !state.mesh_enabled || !state.health?.ok)
    die('migration_conflict: Listener retirement requires a healthy committed AP');
   let plan=local.retirement_preview(state.intent),staged=local.retirement_stage(state.intent,
    'migration-finish-'+m.id+'-'+(m.final_resume || 0)+'-'+(m.final_attempts || 0),plan);
   m.final_transaction_id=staged.id;replace(raw,data);local.apply(staged.id);return;
  }
  if(state.active?.id!=m.final_transaction_id)die('migration_conflict: Listener retirement journal changed');
  if(state.active.status=='staged'){local.apply(m.final_transaction_id);return;}
  if(state.active.status=='awaiting_confirm') {
   if(!state.health?.ok)return;local.confirm(m.final_transaction_id);
  } else if(state.active.status=='rolled_back' || state.active.status=='expired') {
   delete m.final_transaction_id;m.final_attempts=(m.final_attempts || 0)+1;
   m.error='listener_retirement_recovered';replace(raw,data);return;
  } else if(state.active.status=='rollback_conflict') {
   die('ownership_conflict: Listener retirement preserved external changes');
  } else if(state.active.status!='committed')return;
 }
 m.phase='complete';m.error=null;delete data.authority_fence;replace(raw,data);
 if(data.id==m.source) {
  let cluster=durable.load('cluster.json');
  if(cluster?.migration?.id==m.id){cluster.migration.phase='complete';durable.save('cluster.json',cluster);}
 }
}
function tick() {
 durable.locked(()=>{
  let raw=durable.read('identity.json'),data=json(raw),m=data.migration;
  if(data.role!='ap' || !m || index(['complete','cancelled','expired','switched'],m.phase)>=0)return;
  try{local_progress(raw,data,m,agent_local().migration_status());}
  catch(e){if(match(e.message || '',/^busy: /))return;m.error=match(e.message || '',/^([a-z_]+):/)?.[1] || 'migration_conflict';replace(raw,data);}
 });
}
function command_inner(command) {
 if(!match(command?.action || '',/^migration_/))return false;
 if(command.action=='migration_finish') {
  return durable.locked(()=>{
   let raw=durable.read('identity.json'),data=json(raw),m=data.migration;
   if(data.role!='ap' || !m || m.id!=command.transaction ||
    data.binding?.controller_id!=m.target || data.authority_epoch!=m.epoch ||
    command.epoch!=m.epoch || command.token!=m.token || command.target!=m.target || command.source!=m.source ||
    !equal(command.anchor,m.anchor) || !equal(command.binding,m.binding) || command.network_id!=data.binding.network_id ||
    type(command.resume)!='int' || command.resume<0 || command.resume<(m.final_resume || 0))
    die('migration_conflict: Migration completion does not match the active controller');
   if(m.phase=='complete')return true;
   if(index(['switched','finishing'],m.phase)<0)die('migration_conflict: Node has not switched to the new controller');
   if(m.phase!='finishing' || (command.resume || 0)!=(m.final_resume || 0)) {
    m.phase='finishing';m.final_resume=command.resume || 0;m.final_attempts=0;replace(raw,data);raw=durable.read('identity.json');
   }
   finish_progress(raw,data,m,agent_local().migration_status());
   return true;
  });
 }
 // The receipt below is independently verified against the pinned NEW Root,
 // outside the old Root journal lock, before replacing any binding.
 if(command.action=='migration_switch') {
  let before=durable.load('identity.json'),m=validate_source(before,command);
  if(!m || m.phase!='committed' || !equal(m.binding,command.binding) || m.token!=command.token)
   die('migration_conflict: Node switching requires the committed reviewed candidate');
  let proof=exchange({...m.binding,address:m.binding.control_address},
   {protocol:1,network_id:m.binding.network_id,action:'migration_status',migration_id:m.id,token:m.token},false,
   before.id==m.anchor.id ? 'br-mm-ctl' : 'mm-cw',10000);
  if(proof?.active!==true || proof.id!=m.id || proof.epoch!=m.epoch || proof.token!=m.token ||
   proof.controller_id!=m.target || proof.network_id!=m.binding.network_id)
   die('migration_conflict: New controller did not prove the reviewed authority');
  durable.locked(()=>{
   let raw=durable.read('identity.json'),data=json(raw),current=validate_source(data,command);
   if(!current || !equal(current,m))die('storage_conflict: Original migration binding changed during verification');
   data.binding=clone(m.binding);data.anchor=clone(m.anchor);data.authority_epoch=m.epoch;
   data.overrides=clone(m.settings);data.migration={id:m.id,phase:'switched',epoch:m.epoch,
    source:m.source,target:m.target,anchor:clone(m.anchor),binding:clone(m.binding),token:m.token};
   replace(raw,data);
  });return true;
 }
 return durable.locked(()=>{
  let raw=durable.read('identity.json'),data=json(raw),m=validate_source(data,command),local=agent_local(),state=local.migration_status();
  if(command.action=='migration_prepare') {
   if(m) {
    if(m.phase=='preparing') {
     let plan=local.migration_preview(m.intent);m.plan=plan;m.phase=length(plan.errors)?'error':'ready';replace(raw,data);
    }
    return true;
   }
   if(data.handoff || data.departing || state.active && index(TERMINAL,state.active.status)<0 ||
    !state.mesh_enabled || length(state.drift || []) || state.health?.ok!==true)
    die('migration_unavailable: Migration requires a healthy enrolled node without pending recovery');
   try{migration_budget(0);resource_wait=null;}catch(e){
    // Before admission, let other event loops reclaim short-lived captures.
    // Every attempt repeats the unchanged native gate. Five deferrals are
    // bounded by the original coordinator deadline and write no receipt.
    if(match(e.message || '',/^insufficient_resources: /)) {
     let attempts=resource_wait?.id==command.transaction ? resource_wait.attempts : 0;
     if(attempts<5) {
      resource_wait={id:command.transaction,attempts:attempts+1};
      die('busy: Waiting for the original migration resource reserve');
     }
    }
    resource_wait=null;
    // Report a finite rejection without admitting any configuration or key.
    data.migration={id:command.transaction,phase:'error',epoch:command.epoch,
     source:command.source,target:command.target,anchor:clone(command.anchor),binding:clone(command.binding),token:command.token,
     version:command.version,error:match(e.message || '',/^([a-z_]+):/)?.[1] || 'resource_unavailable'};
    replace(raw,data);die(e.message);
   }
   let settings=effective_settings(data,durable.load('state.json')),
    mapped={...settings,peers:data.id==command.anchor.id ? clone(command.peers) : [mesh_mac(command.anchor.id)]};
   let intent=local_intent(command.intent,mapped,data.id==command.target,command.anchor.gateway,data.id,
    command.control ? require_lease(command.control) : null,command.anchor);
   if(data.id==command.target && durable.read('network-ca.key')!=null)
    die('storage_conflict: Target already holds a controller signing key');
   data.migration={id:command.transaction,phase:'preparing',epoch:command.epoch,
    source:command.source,target:command.target,anchor:clone(command.anchor),binding:clone(command.binding),token:command.token,
    version:command.version,created:time(),intent,settings,before_intent:clone(state.intent),plan:null,
    cluster_before:crypto.sha256(durable.read('cluster.json') || 'absent')};
   replace(raw,data);raw=durable.read('identity.json');
   let plan=local.migration_preview(intent);
   data.migration.plan=plan;data.migration.phase=length(plan.errors)?'error':'ready';
   replace(raw,data);return true;
  }
  if(!m && command.action=='migration_cancel') {
   data.migration={id:command.transaction,phase:'cancelled',epoch:command.epoch,source:command.source,target:command.target};
   replace(raw,data);return true;
  }
  if(!m)die('migration_conflict: No reviewed migration is pending');
  if(!equal(m.binding,command.binding) || !equal(m.anchor,command.anchor) || m.token!=command.token)
   die('migration_conflict: The reviewed migration changed');
  if(command.action=='migration_apply') {
   if(index(['committed','transferring','transferred','promoting'],m.phase)>=0)return true;
   if(m.transaction_id) {
    if(state.active?.id!=m.transaction_id)die('migration_conflict: Migration transaction changed');
    if(state.active.status=='staged')local.apply(m.transaction_id);
    return true;
   }
   if(m.phase!='ready' || !equal(m.plan,command.approval))die('preview_changed: Review the changed migration preview');
   let stage=local.migration_stage(m.intent,'migration-'+m.id,true,command.approval);
   m.transaction_id=stage.id;m.phase='applying';replace(raw,data);local.apply(stage.id);return true;
  }
  if(command.action=='migration_confirm') {
   if(m.phase=='committed')return true;
   if(!m.transaction_id || state.active?.id!=m.transaction_id || state.health?.ok!==true)
    die('unhealthy: Migration configuration is not ready for confirmation');
   local.confirm(m.transaction_id);m.phase='committed';m.metadata_committed=true;replace(raw,data);return true;
  }
  if(command.action=='migration_chunk') {
   if(data.id!=m.target || index(['committed','transferring','transferred'],m.phase)<0 || command.fenced!==true)
    die('migration_conflict: Authority transfer requires the reviewed target and source fence');
   migration_budget(command.total*8192);
   if(validate_chunk(m,command)){m.chunks=m.chunks || [];push(m.chunks,command.data);}
   m.hash=command.hash;m.total=command.total;m.fenced=true;m.phase=length(m.chunks)==m.total ? 'transferred' : 'transferring';
   if(m.phase=='transferred')ready_transfer(data,m);
   replace(raw,data);return true;
  }
  if(command.action=='migration_activate') {
   if(data.id!=m.target || command.fenced!==true || command.hash!=m.hash ||
    index(['transferred','promoting'],m.phase)<0)die('migration_conflict: Promotion requires the complete fenced transfer');
   promote(raw,data,m);return true;
  }
  if(command.action=='migration_cancel') {
   if(m.fenced || index(['transferring','transferred','promoting'],m.phase)>=0)
    die('migration_fenced: Resume the transferred authority before migrating back');
   if(m.phase=='cancelled')return true;
   if(m.phase=='cancelling')return true;
   if(m.transaction_id && state.active?.id!=m.transaction_id)
    die('migration_conflict: Migration cancellation journal changed');
   if(m.metadata_committed || m.transaction_id && state.active.status=='committed') {
    let plan=local.migration_preview(m.before_intent);
    if(length(plan.errors))die('ownership_conflict: Migration cancellation cannot overwrite external changes');
    let stage=local.migration_stage(m.before_intent,'migration-cancel-'+m.id,true,plan);
    m.cancel_transaction_id=stage.id;m.phase='cancelling';replace(raw,data);local.apply(stage.id);
   } else if(m.transaction_id && index(TERMINAL,state.active.status)<0) {
    m.phase='cancelling';replace(raw,data);local.rollback(m.transaction_id);
   } else {m.phase='cancelled';replace(raw,data);}
   return true;
  }
  die('invalid_method: Unknown migration command');
 });
}
function command(command) {
 try{return command_inner(command);}
 catch(e) {
  if(match(e.message || '',/^busy: /))die(e.message);
  durable.locked(()=>{
   let raw=durable.read('identity.json'),data=json(raw),m=data.migration;
   if(data.role!='ap' || m?.id!=command?.transaction)return;
   m.error=match(e.message || '',/^([a-z_]+):/)?.[1] || 'migration_conflict';
   if(index(['preparing','ready','applying','awaiting_confirm'],m.phase)>=0 && !m.fenced)m.phase='error';
   replace(raw,data);
  });die(e.message);
 }
}

return {tick,command};
}
