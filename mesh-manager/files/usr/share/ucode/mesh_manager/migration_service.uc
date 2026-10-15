// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as crypto from 'mesh_crypto';
import {clone,equal} from './model.uc';
import {effective_settings} from './local_settings.uc';
import {local_intent,mesh_mac} from './extended.uc';
import {private_address} from './identity.uc';
import {allocate_lease,adopt_leases,require_lease,lease_table} from './control_lease.uc';
import {require_anchor} from './authority.uc';
import {migration_id,migration_binding,migration_pending,public_migration,transfer_state,CHUNK_SIZE,TRANSFER_LIMIT} from './migration_model.uc';
import {migration_budget as native_budget} from './migration_budget.uc';
import {public_signer} from './config_signing.uc';

const FINAL=['complete','partial','failed','rolled_back','cancelled','expired'];
const LOCAL_FINAL=['committed','rolled_back','rollback_conflict','expired'];
function failure(e){return match(e.message || '',/^([a-z_]+):/)?.[1] || 'migration_conflict';}
export function migration_service(io) {
 const migration_budget=io.budget || native_budget;
 function save(s){io.save('cluster.json',s);}
 function identity_replace(data){io.write_cas('identity.json',io.read('identity.json'),sprintf('%J',data),5000);}
 function state(){return io.load('cluster.json');}
 function status(plans){return public_migration(state()?.migration,plans);}
 function anchor(root) {
  return root.anchor ? require_anchor(root.anchor) : require_anchor({id:root.id,address:root.address,
   control_address:'169.254.254.1',gateway:root.gateway || 'router',certificate:crypto.fingerprint(io.read('device.crt'))});
 }
 function fresh(s,root) {
  let local=io.local.migration_status(),a=anchor(root);
  if(!local.mesh_enabled || local.health?.ok!==true || length(local.drift || []) ||
   local.active && index(LOCAL_FINAL,local.active.status)<0)
   die('migration_unavailable: Controller migration requires a healthy committed local configuration');
  for(let id in keys(s.members)) {
   let member=s.members[id];if(!member.authorized)continue;
   let seen=io.presence(id),report=member.report;
   if(member.mesh_paused || member.version!=s.version || report?.mesh_enabled!==true ||
    type(report.drift)!='array' || length(report.drift) || member.control_protocol!==1 ||
    seen?.boot!=io.boot() || io.now()-seen.seen<0 || io.now()-seen.seen>=15 ||
    !(report.backhaul?.active=='wired' && report.backhaul?.wired===true ||
     id==a.id && report.data_gateway===true && report.backhaul?.active=='gateway'))
    die('migration_unavailable: Every authorized node must be synchronized on a fresh authenticated wired path');
  }
  return local;
 }
 function preflight(target,id) {
  let root=io.load('identity.json'),s=state();
  if(root?.role!='root' || root.authority_fence)die('not_controller: This node cannot authorize a controller migration');
  if(!migration_id(id) || !migration_id(target) || target==root.id || !s?.members?.[target]?.authorized)
   die('invalid_request: Select an authorized AP as the migration target');
  if(s.migration?.id==id) {
   if(s.migration.target!=target)die('request_reused: Migration request belongs to another target');
   return status();
  }
  if(migration_pending(s.migration) ||
   length(filter([s.active,s.lifecycle],job=>job && index(FINAL,job.phase)<0)) ||
   length(filter(values(s.members),member=>member.repair && index(['committed','failed','rolled_back','expired','cancelled'],member.repair.status)<0)) ||
   length(filter(values(s.requests),request=>request.status=='pending')))
   die('busy: Complete the pending network operation before migration');
  let local=fresh(s,root),a=anchor(root),member=s.members[target],leases=adopt_leases(s),
   addresses=member.report?.management?.addresses || [],address=filter(addresses,row=>private_address(row.address))[0]?.address;
  if(target==a.id)address=a.address;
  if(!private_address(address) || target!=a.id && address==a.address)
   die('migration_unavailable: Target must report a distinct private management address');
  let epoch=(root.authority_epoch || 1)+1,binding={controller_id:target,network_id:root.network_id,address,
   control_address:target==a.id ? a.control_address : leases[target].wired,controller_certificate:member.certificate,
   ca_fingerprint:crypto.fingerprint(io.read('network-ca.crt')),epoch};
  if(!migration_binding(binding))die('migration_unavailable: Target certificate or control address is unavailable');
  let roster=clone(s);delete roster.members[target];
  roster.reserved_control=target==a.id ? null : require_lease(member.control);
  let control=root.id!=a.id && root.control ? require_lease(root.control) : allocate_lease(roster,root.id);
  roster.members[root.id]={control};lease_table(roster);
  let settings=effective_settings(root,io.load('state.json')),
   mapped={...settings,peers:root.id==a.id ? map(filter(keys(s.members),n=>s.members[n].authorized),mesh_mac) : [mesh_mac(a.id)]},
   intent=local_intent(s.intent,mapped,false,a.gateway,root.id,control,a),plan=io.local.migration_preview(intent);
  if(length(plan.errors))die('preflight_failed: Source controller migration candidate failed preflight');
  migration_budget(0);
  let m={id,phase:'preflight',source:root.id,target,source_certificate:crypto.fingerprint(io.read('device.crt')),
   epoch,version:s.version,created:time(),boot:io.boot(),deadline:io.now()+300,anchor:a,binding,token:io.random(32),
   nodes:{},root:{status:'ready',plan,intent,before_intent:clone(local.intent),settings,control},joined:[],fenced:false};
  for(let node in keys(s.members))if(s.members[node].authorized)m.nodes[node]={status:'pending',plan:null};
  s.migration=m;save(s);
  root.migration={id,phase:'preflight',source:root.id,target,epoch,anchor:clone(a),binding:clone(binding),token:m.token};
  identity_replace(root);
  return status();
 }
 function apply(id,approval,takeover) {
  let s=state(),m=s?.migration,root=io.load('identity.json');
  if(!m || m.id!=id || root?.id!=m.source || root.role!='root')die('not_found: Controller migration preview not found');
  if(takeover!==true)die('takeover_required: Approve the controller migration preview');
  if(m.phase!='ready') {
   if(index(['applying','transferring','handover','switching','finishing','complete'],m.phase)>=0)return status();
   die('invalid_state: All-node migration preflight is not ready');
  }
  if(!equal(approval,public_migration(m)) || m.boot!=io.boot() || io.now()>=m.deadline)
   die('preview_changed: Refresh and review the controller migration again');
  fresh(s,root);
  m.phase='applying';m.deadline=io.now()+600;save(s);return status();
 }
 function cancel(id) {
  let s=state(),m=s?.migration;
  if(!m || m.id!=id)die('not_found: Controller migration not found');
  if(m.fenced || index(['transferring','handover','switching','complete'],m.phase)>=0)
   die('migration_fenced: Resume the new authority before migrating back');
  if(m.phase=='cancelled')return status();
  if(index(['preflight','ready','applying','failed','cancelling'],m.phase)<0)
   die('invalid_state: Only an unfenced migration can be cancelled');
  m.phase='cancelling';save(s);return status();
 }
 function resume(id) {
  let s=state(),m=s?.migration;
  if(!m || m.id!=id)die('not_found: Controller migration not found');
  if(m.fenced!==true)die('invalid_state: An unfenced migration needs a new reviewed preview or cancellation');
	 m.failure=null;m.resume=(m.resume || 0)+1;save(s);return status();
 }
 function command(s,id,action,extra) {
  let m=s.migration;
  return {id:m.id+'-'+action,action,transaction:m.id,source:m.source,target:m.target,network_id:m.binding.network_id,
   version:m.version,epoch:m.epoch,anchor:clone(m.anchor),binding:clone(m.binding),token:m.token,resume:m.resume || 0,
   ...(extra || {})};
 }
 function collect(s,id,r) {
  let root=io.load('identity.json'),member=s.members[id];
  io.seen?.(id);
  if(type(r.report)!='object' || length(sprintf('%J',r.report))>=40000)
   die('invalid_request: Migration requires a bounded node report');
  let report=io.sanitize_report(r.report),persisted=clone(report);delete persisted.clients;delete persisted.health;
  if(r.report.migration!=null && report.migration==null)die('protocol_error: Invalid migration receipt');
  if(type(persisted.backhaul)=='object')delete persisted.backhaul.quality;
  try{io.observe_report?.(id,report,{controller_id:root.id,network_id:root.network_id,certificate:member.certificate});}catch(e){}
  member.report=persisted;member.version=report.version || 0;member.control_protocol=r.control_schema===1?1:0;
  let receipt=report.migration,node=s.migration.nodes[id];
  if(node && receipt?.id==s.migration.id && receipt.epoch==s.migration.epoch) {
   node.status=receipt.phase;node.error=receipt.error || null;node.received=receipt.received || 0;
   if(receipt.plan!=null)node.plan=clone(receipt.plan);
   if(receipt.phase=='awaiting_confirm' && report.health?.ok!==true)node.status='applying';
   if(index(['switched','complete'],receipt.phase)>=0 && report.version==s.version && report.mesh_enabled===true &&
    type(report.drift)=='array' && !length(report.drift) && index(s.migration.joined,id)<0)
    push(s.migration.joined,id);
  }
 }
 function peer(id,r,certificate,destination) {
  let root=io.load('identity.json'),s=state(),m=s?.migration;
  if(!m)return null;
  if(r.action=='migration_status') {
   if(root.role!='root' || root.id!=m.target || !s.members[id]?.authorized ||
    s.members[id].certificate!=certificate || r.network_id!=root.network_id || r.migration_id!=m.id ||
    r.token!=m.token || destination!=(root.control_address || '169.254.254.1'))
    die('not_authorized: New controller authority proof is unavailable');
   return {controller_id:root.id,network_id:root.network_id,active:true,id:m.id,epoch:m.epoch,token:m.token,phase:m.phase};
  }
  if(!migration_pending(m) && m.phase!='complete')return null;
  if(r.action!='poll' || !s.members[id]?.authorized || s.members[id].certificate!=certificate ||
   r.network_id!=m.binding.network_id || r.protocol!==1 ||
   destination!=(root.control_address || '169.254.254.1'))
   die('migration_pending: Use the isolated migration control connection');
  let old=sprintf('%J',s);collect(s,id,r);m=s.migration;
  if(root.id==m.target) {
   if(m.phase=='switching' && length(m.joined)==length(keys(m.nodes)))m.phase='finishing';
   if(m.phase=='finishing' && !length(filter(values(m.nodes),n=>n.status!='complete')))m.phase='complete';
   if(sprintf('%J',s)!=old)save(s);
   return {controller_id:root.id,network_id:root.network_id,version:s.version,
    command:index(['finishing','complete'],m.phase)>=0 && s.members[id].report?.migration?.phase!='complete' ?
     command(s,id,'migration_finish') : null};
  }
  let node=m.nodes[id],next=null;
  if(m.phase=='preflight' && !node.plan && node.status!='error')next=command(s,id,'migration_prepare',{
   intent:clone(s.intent),control:clone(s.members[id].control),
   peers:map([m.source,...filter(keys(s.members),n=>s.members[n].authorized && n!=id)],mesh_mac)});
  if(m.phase=='applying') {
   if(node.status=='ready')next=command(s,id,'migration_apply',{approval:clone(node.plan)});
   else if(node.status=='awaiting_confirm')next=command(s,id,'migration_confirm');
  }
  if(m.phase=='cancelling' && node.status!='cancelled')next=command(s,id,'migration_cancel');
  if(m.fenced) {
   if(id==m.target && root.role=='root' && m.material) {
    let total=int((length(m.material)+CHUNK_SIZE-1)/CHUNK_SIZE),index=node.received || 0;
    if(index<total)next=command(s,id,'migration_chunk',{fenced:true,hash:m.hash,total,index,
     data:substr(m.material,index*CHUNK_SIZE,CHUNK_SIZE)});
    else next=command(s,id,'migration_activate',{fenced:true,hash:m.hash});
   } else next=command(s,id,'migration_switch');
  }
  if(sprintf('%J',s)!=old)save(s);
  return {controller_id:m.source,network_id:m.binding.network_id,version:s.version,command:next};
 }
 function metadata(s) {
  let m=s.migration,root=m.root,local=io.local.migration_status();
  if(!root.transaction_id) {
   let staged=io.local.migration_stage(root.intent,'migration-'+m.id,true,root.plan);
   root.transaction_id=staged.id;root.status='applying';save(s);io.local.apply(staged.id);return;
  }
  if(local.active?.id!=root.transaction_id)die('migration_conflict: Source controller migration journal changed');
  if(local.active.status=='staged'){io.local.apply(root.transaction_id);return;}
  if(local.active.status=='awaiting_confirm') {
   if(!local.health?.ok)return;
   io.local.confirm(root.transaction_id);root.status='committed';save(s);return;
  }
  if(local.active.status=='committed')root.status='committed';
  if(index(['rolled_back','rollback_conflict','expired'],local.active.status)>=0) {
   root.status='error';root.error=local.active.status;die('migration_conflict: Source migration candidate recovered before confirmation');
  }
 }
 function cleanup(s) {
  let m=s.migration,root=m.root,local=io.local.migration_status();
  if(root.transaction_id) {
   let id=root.cancel_transaction_id || root.transaction_id;
   if(local.active?.id!=id)die('migration_conflict: Source cancellation journal changed');
   if(!root.cancel_transaction_id && local.active.status=='committed') {
    let plan=io.local.migration_preview(root.before_intent);
    if(length(plan.errors))die('ownership_conflict: Source migration cancellation cannot overwrite external changes');
    let staged=io.local.migration_stage(root.before_intent,'migration-cancel-'+m.id,true,plan);
    root.cancel_transaction_id=staged.id;save(s);io.local.apply(staged.id);return;
   }
   if(root.cancel_transaction_id && index(['rolled_back','expired'],local.active.status)>=0) {
    if((root.cancel_attempts || 0)>=3)
     die('migration_conflict: Source cancellation recovered repeatedly; review its recovery journal');
    let plan=io.local.migration_preview(root.before_intent);
    if(length(plan.errors))die('ownership_conflict: Source migration cancellation cannot overwrite external changes');
    let attempt=(root.cancel_attempts || 0)+1,
     staged=io.local.migration_stage(root.before_intent,'migration-cancel-'+m.id+'-'+attempt,true,plan);
    root.cancel_attempts=attempt;root.cancel_transaction_id=staged.id;save(s);io.local.apply(staged.id);return;
   }
   if(root.cancel_transaction_id && local.active.status=='staged') {
    io.local.apply(id);return;
   }
   if(root.cancel_transaction_id && local.active.status=='awaiting_confirm') {
    if(!local.health?.ok)return;io.local.confirm(id);return;
   }
   if(!root.cancel_transaction_id && index(LOCAL_FINAL,local.active.status)<0){io.local.rollback(id);return;}
   if(local.active.status=='rollback_conflict')die('ownership_conflict: Source migration cancellation preserved external changes');
   if(root.cancel_transaction_id && local.active.status!='committed' || !root.cancel_transaction_id && local.active.status=='committed')return;
  }
  if(length(filter(values(m.nodes),n=>n.status!='cancelled')))return;
  m.phase='cancelled';save(s);let identity=io.load('identity.json');
  if(identity.migration?.id==m.id){delete identity.migration;identity_replace(identity);}
 }
 function fence(s) {
  let m=s.migration,root=io.load('identity.json');
  fresh(s,root);
  let key=io.read('network-ca.key'),ca=io.read('network-ca.crt'),
   cluster=transfer_state(s,m,m.source_certificate,m.root.settings,m.root.control),
   payload={schema:1,id:m.id,epoch:m.epoch,network_id:root.network_id,anchor:clone(m.anchor),binding:clone(m.binding),
    ca_crt:ca,ca_key:key,cluster},material=sprintf('%J',payload);
  if(!key || length(material)>TRANSFER_LIMIT || length(material)>210000)
   die('migration_limit: Controller state exceeds the bounded transfer capacity');
  migration_budget(length(material));
  // Persist the fence BEFORE publishing any activation material. If saving the
  // coordinator then fails, the old Root stays fenced and resumes this epoch.
  root.authority_fence={id:m.id,epoch:m.epoch,target:m.target,token:m.token};root.anchor=clone(m.anchor);
  root.migration={id:m.id,phase:'transferring',source:m.source,target:m.target,epoch:m.epoch,
   anchor:clone(m.anchor),binding:clone(m.binding),token:m.token};identity_replace(root);
  m.config_signing_hash=s.config_signing ? crypto.sha256(sprintf('%J',s.config_signing)) : null;
  m.fenced=true;m.phase='transferring';m.material=material;m.hash=crypto.sha256(material);save(s);
 }
 function tick_locked() {
  let s=state(),m=s?.migration,root=io.load('identity.json');
  if(!m || root?.id!=m.source || root.role!='root' || index(['complete','cancelled'],m.phase)>=0)return;
  try {
   if(root.authority_fence && !m.fenced) {
    if(root.authority_fence.id!=m.id || root.authority_fence.epoch!=m.epoch)
     die('migration_conflict: Source authority fence changed');
    fence(s);return;
   }
   if(!m.fenced && (m.boot!=io.boot() || io.now()>=m.deadline) && m.phase!='cancelling') {
    m.phase='failed';m.failure='migration_expired';save(s);return;
   }
   if(m.phase=='preflight') {
    let nodes=values(m.nodes);
    if(length(filter(nodes,n=>n.status=='error'))) {m.phase='failed';m.failure='preflight_failed';}
    else if(!length(filter(nodes,n=>n.status!='ready' || !n.plan || length(n.plan.errors || []))))m.phase='ready';
    else return;save(s);return;
   }
   if(m.phase=='cancelling'){cleanup(s);return;}
   if(m.phase=='applying') {
    if(length(filter(values(m.nodes),n=>n.status=='error'))){m.phase='failed';m.failure='node_recovered';save(s);return;}
    metadata(s);
    if(m.root.status=='committed' && !length(filter(values(m.nodes),n=>n.status!='committed')))fence(s);
   }
  } catch(e) {
   if(failure(e)=='busy')return;
   m.failure=failure(e);if(!m.fenced && !root.authority_fence)m.phase='failed';save(s);
  }
 }
 // Fresh proof is obtained outside the source lock. A missing/partitioned
 // target cannot revive old authority or remove the source signing key.
 function handover() {
  let frame=io.locked(()=>({root:io.load('identity.json'),state:state()})),m=frame.state?.migration;
  if(frame.root?.role!='root' || !frame.root.authority_fence || !m?.fenced)return;
  let proof;
  try{proof=io.exchange({...m.binding,address:m.binding.control_address},
   {protocol:1,network_id:m.binding.network_id,action:'migration_status',migration_id:m.id,token:m.token},false,
   frame.root.id==m.anchor.id ? 'br-mm-ctl' : 'mm-cw',10000);}catch(e){return;}
  if(proof?.active!==true || proof.id!=m.id || proof.epoch!=m.epoch || proof.token!=m.token ||
   proof.controller_id!=m.target || proof.network_id!=m.binding.network_id)return;
  io.locked(()=>{
   let s=state(),root=io.load('identity.json'),current=s.migration;
   if(root.role!='root' || !equal(root.authority_fence,frame.root.authority_fence) ||
    current.id!=m.id || current.hash!=m.hash || !current.fenced)
    die('storage_conflict: Source authority changed during handover verification');
   // Erase copied signing material before key retirement, then publish AP role.
   // After a crash, the fresh target proof permits retirement to resume.
   if(current.material){
    if((s.config_signing ? crypto.sha256(sprintf('%J',s.config_signing)) : null)!==current.config_signing_hash)
     die('storage_conflict: Source configuration signing key changed before retirement');
    current.signing_public=public_signer(s,root.network_id);delete s.config_signing;
    current.ca_hash=crypto.sha256(io.read('network-ca.key'));delete current.material;current.phase='handover';save(s);
   }
   let key=io.read('network-ca.key');
   if(key!=null) {
    if(crypto.sha256(key)!=current.ca_hash)die('storage_conflict: Source signing key changed before retirement');
    io.remove_ca_key(key);
   }
   root.role='ap';root.binding=clone(m.binding);root.authority_epoch=m.epoch;root.anchor=clone(m.anchor);
   root.ca_fingerprint=m.binding.ca_fingerprint;
   root.cluster_version=m.version;root.overrides=clone(m.root.settings);delete root.agent;
   if(current.signing_public)root.signing=clone(current.signing_public);
   root.migration={id:m.id,phase:'switched',epoch:m.epoch,source:m.source,target:m.target,
    anchor:clone(m.anchor),binding:clone(m.binding),token:m.token};
   s.roster_authority=clone(m.binding);save(s);identity_replace(root);
  });
 }
 return {preflight,apply,cancel,resume,status,peer,tick_locked,handover};
}
