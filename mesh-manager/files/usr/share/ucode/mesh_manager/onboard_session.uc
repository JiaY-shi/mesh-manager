// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal, canonical } from './model.uc';
import { standby_authority } from './standby.uc';

const TRANSITION=['role','name','overrides','joining','binding','network_id','agent','cluster_version','handoff'];
const WITNESS=['schema','origin_tag','key','join_ca','network_ca','cert','requesting','pending','ap','approved_ca','approved_cert','code'];
const HANDOFF=['schema','request','joining','epoch','identity','key','ca','cert','journal','journal_base','snapshot','proof'];
function unchanged_fields(v) {
 let result=clone(v);for(let key in TRANSITION)delete result[key];return result;
}
function pinned(binding,code) {
 return type(binding)=='object' && binding.address==code.address &&
  (binding.ca_fingerprint ?? binding.fingerprint)==code.fingerprint &&
  match(binding.controller_id || '',/^[0-9a-f]{32}$/)!=null &&
  match(binding.network_id || '',/^[0-9a-f]{32}$/)!=null;
}
function joining_witness(joining,approved) {
 let result=clone(joining);delete result.status;
 if(approved)delete result.approval;
 return result;
}
function pending_base(identity) {
 let result=clone(identity);delete result.joining.approval;return result;
}
export function expected_ap(identity,handoff) {
 let result=pending_base(identity),v=result.joining.invitation;
 result.binding={address:v.address,controller_id:v.controller_id,network_id:v.network_id,
  port:v.port,ca_fingerprint:v.fingerprint};
 result.network_id=v.network_id;result.role='ap';result.joining=null;
 if(handoff!=null)result.handoff=clone(handoff);
 return result;
}
function raw_scope(scope) {return {...scope,identity:scope.raw_identity || sprintf('%J',scope.identity)};}
function pending_raw(base,status) {let result=clone(base);result.joining.status=status;return sprintf('%J',result);}

function raw_hash(verify,raw) {
 if(raw==null)return null;
 let value=verify.digest(raw);
 if(type(raw)!='string' || type(value)!='string' || !match(value,/^[0-9a-f]{64}$/))
  die('runtime_unavailable: Native authority digest unavailable');
 return value;
}
function proof_hash(verify,key,raw) {
 let value=verify.hmac(raw_hash(verify,key),raw);
 if(type(value)!='string' || !match(value,/^[0-9a-f]{64}$/))
  die('runtime_unavailable: Native authority proof unavailable');
 return value;
}
function approval(current,checkpoint,initial,seen,verify,original) {
 if(checkpoint?.handoff==null)return verify.approval?.(raw_scope(current),checkpoint,original);
 let permitted=seen?.permit?.handoff;
 if(permitted)return verify.transport_approval?.(raw_scope(current),checkpoint,original,permitted);
 // A partial durable CP9 may be resumed only after a single complete baseline
 // capture. This is never inferred from a proof-valid ref on an arbitrary AP.
 if(initial?.mode=='resume' && initial.identity?.joining?.approval?.handoff!=null &&
  equal(initial.identity.joining.approval.handoff,checkpoint.handoff) &&
  ('state' in initial) && type(initial.snapshot)=='string')
  return verify.approval?.({...raw_scope(current),state:initial.state,snapshot:initial.snapshot},checkpoint,original);
 return null;
}
function handoff_permit_valid(base,current,w,verify) {
 let ref=w.handoff,e=base?.enrollment,j=base?.joining;
 if(type(ref)!='object' || !equal(sort(keys(ref)),sort(HANDOFF)) || ref.schema!==1 ||
  e?.enabled!==true || type(e.ssid)!='string' || length(e.ssid)<1 || length(e.ssid)>32 ||
  type(e.password)!='string' || length(e.password)<8 || length(e.password)>63 ||
  ref.request!==j?.request_id || ref.epoch!==e.epoch || !match(ref.request || '',/^[0-9a-f]{32}$/) ||
  !match(ref.epoch || '',/^[0-9a-f]{32}$/) ||
  length(filter(['joining','identity','key','ca','cert','journal_base','snapshot','proof'],k=>!match(ref[k] || '',/^[0-9a-f]{64}$/))) ||
  ref.journal!=null && !match(ref.journal || '',/^[0-9a-f]{64}$/))return false;
 let unapproved=clone(j);delete unapproved.approval;
 // The actor may first see requesting, then receive a checkpoint for pending.
 // onboard_authority has already proved that only this status changed. Hash
 // the exact current status for the handoff, preserving every other raw field.
 if(index(['requesting','pending'],current.identity?.joining?.status)<0)return false;
 unapproved.status=current.identity.joining.status;
 let bare=expected_ap(base);delete bare.agent;delete bare.cluster_version;
 let unsigned=clone(ref);delete unsigned.proof;
 if(ref.joining!==raw_hash(verify,sprintf('%J',unapproved)) || ref.identity!==raw_hash(verify,sprintf('%J',bare)) ||
  ref.key!==raw_hash(verify,current.key) || ref.ca!==w.approved_ca || ref.cert!==w.approved_cert ||
  ref.proof!==proof_hash(verify,'mesh-manager/first-handoff/identity/v1\n'+current.key,sprintf('%J',canonical(unsigned))))return false;
 if(type(verify.journal)!='function' || raw_hash(verify,verify.journal())!==ref.journal)return false;
 return true;
}
/* Only the already-authorized connection survives the ordinary local join
 * transition. This model never creates requests, certificates or identities. */
export function onboard_authority(initial,current,seen,verify) {
 if(initial?.mode=='discover') {
  // The discovery actor may observe only its unchanged unbound enrollment.
  // It cannot authorize any join, certificate, binding or configuration write.
  if(initial.boot!==current?.boot || initial.raw_identity!==current.raw_identity ||
   initial.identity?.role!='unbound' || initial.identity?.binding || initial.identity?.joining ||
   initial.identity?.enrollment?.enabled!==true || initial.identity.enrollment.code ||
   length(filter(['key','join_ca','network_ca','cert'],k=>initial[k]!==current[k])))return null;
  return {joining:null,binding:null};
 }
 if(initial?.mode=='standby')return standby_authority(initial,current,verify.journal());
 if(type(initial)!='object' || type(current)!='object' || initial.boot!=current.boot ||
  initial.key!=current.key || !initial.code || !current.identity)return null;
 let before=initial.identity,now=current.identity;
 if(initial.mode=='handoff') {
  if(before.role!='ap' || before.joining || !before.handoff || !equal(before.handoff,now.handoff) ||
   !verify.handoff_transport?.(raw_scope(current),before.handoff))return null;
  return {joining:null,binding:clone(now.binding),base:null,permit:seen?.permit || null,handoff:clone(before.handoff)};
 }
 let resume=initial.mode=='resume';
 if(before.role!='unbound' || before.binding || (!resume && before.joining) ||
  (resume && (before.enrollment?.enabled!==true || index(['requesting','pending'],before.joining?.status)<0)) ||
  !equal(unchanged_fields(before),unchanged_fields(now)))return null;
 if(now.role=='unbound') {
  if((initial.join_ca || null)!=(current.join_ca || null) && !verify.ca(current.join_ca,initial.code.fingerprint))return null;
  let approved=now.joining?.approval!=null ? approval(current,now.joining.approval,initial,seen,verify) : null;
  if(now.joining?.approval!=null && !approved)return null;
  let same_material=(initial.network_ca || null)==(current.network_ca || null) && (initial.cert || null)==(current.cert || null);
  if(!same_material && !approved && (!verify.ca(current.network_ca,initial.code.fingerprint) ||
   !verify.leaf(current.network_ca,current.cert,current.key,now.id)))return null;
  // Actual production callbacks use the exact original before/approved-after
  // checkpoint proof for every partial material write. Pure legacy fixtures
  // without a raw capture cannot authorize an actual actor publication.
  if(current.raw_identity && now.joining && !same_material && !approved)return null;
  if(now.binding || now.network_id || now.agent || now.cluster_version)return null;
  if(!now.joining)return resume || seen?.joining || seen?.binding ? null : {joining:null,binding:null};
  let j=now.joining,v=j.invitation;
  if(index(['requesting','pending'],j.status)<0 || !pinned(v,initial.code) || v.token!=initial.code.token ||
   v.port!=37901 || v.enroll_port!=37902 || !match(j.request_id || '',/^[0-9a-f]{32}$/) ||
   !match(j.secret || '',/^[0-9a-f]{64}$/) || !verify.ca(v.ca,initial.code.fingerprint) ||
   current.join_ca!=v.ca)return null;
  let original_approval=before.joining?.approval!=null ? verify.approval?.(raw_scope(initial),before.joining.approval) : null;
  if(before.joining?.approval!=null && !original_approval)return null;
  let witness=joining_witness(j,approved!=null);
  if(resume && !equal(joining_witness(before.joining,original_approval!=null),witness))return null;
  if(seen?.joining && !equal(seen.joining,witness))return null;
  let base=seen?.base || (resume ? pending_base(before) : pending_base(now)),actual=pending_base(now);
  let expected=clone(base);expected.joining.status=j.status;
  if(!equal(expected,actual))return null;
  if(current.raw_identity) {
   if(approved ? approved.base_identity!==sprintf('%J',expected) : current.raw_identity!==sprintf('%J',expected))return null;
  }
  if(seen?.permit && approved && raw_hash(verify,approved.cert)!==seen.permit.approved_cert)return null;
  return {joining:witness,binding:null,base,approval:approved?.checkpoint || seen?.approval || null,
   approval_base:approved?.base_identity || seen?.approval_base || null,permit:seen?.permit || null};
 }
 if(now.role!='ap' || now.joining || !pinned(now.binding,initial.code) ||
  now.binding.port!=37901 || now.network_id!=now.binding.network_id ||
  !verify.ca(current.network_ca,initial.code.fingerprint) ||
  !verify.leaf(current.network_ca,current.cert,current.key,now.id))return null;
 if(current.join_ca!=null && (initial.join_ca || null)!=current.join_ca && !verify.ca(current.join_ca,initial.code.fingerprint))return null;
 if(seen?.joining && (now.binding.controller_id!=seen.joining.invitation.controller_id ||
  now.binding.network_id!=seen.joining.invitation.network_id))return null;
 if(seen?.binding && !equal(seen.binding,now.binding))return null;
 let base=seen?.base || (resume ? pending_base(before) : null),handoff=seen?.permit?.handoff || seen?.approval?.handoff;
 let expected=base ? expected_ap(base,handoff) : null;
 if(handoff) {
  if(!verify.handoff_transport?.(raw_scope(current),handoff))return null;
 }else if(base && (!equal(expected,now) || current.raw_identity && current.raw_identity!==sprintf('%J',expected)))return null;
 if(current.raw_identity && (!base || !seen?.permit && !seen?.approval))return null;
 if(seen?.permit && (raw_hash(verify,current.cert)!==seen.permit.approved_cert ||
  raw_hash(verify,current.network_ca)!==seen.permit.approved_ca))return null;
 if(seen?.approval && (!handoff || equal(expected,now)) &&
  !approval(current,seen.approval,initial,seen,verify,seen.approval_base || pending_raw(base,base.joining.status)))return null;
 return {joining:seen?.joining || null,binding:clone(now.binding),base,approval:seen?.approval || null,
  approval_base:seen?.approval_base || null,permit:seen?.permit || null};
}
export function onboard_projection(value) {
 if(value==null)return {active:false};
 if(type(value)!='object' || value.schema!=1 || value.verified!==true || value.error!=null ||
  type(value.ssid)!='string' || length(value.ssid)<1 || length(value.ssid)>32 ||
  type(value.connected)!='bool' || type(value.deadline)!='int' || type(value.now)!='int' ||
  value.now>=value.deadline || value.now<value.observed || value.now-value.observed>6500)
  return {active:true,connected:false,error:value?.error=='cleanup_conflict' ? 'cleanup_conflict' : 'runtime_unavailable'};
 return {active:true,connected:value.connected,ssid:value.ssid,remaining:int((value.deadline-value.now)/1000)};
}
/* Whole raw snapshots (including private passwords/unknown fields) gate every
 * late callback. Equality of the displayed redacted view has no authority. */
export function onboard_frame_valid(frame,current,now) {
 return type(frame)=='object' && type(current)=='object' && equal(frame.scope,current) &&
  type(now)=='int' && now>=frame.started && now<frame.deadline;
}

/* Private fixed-size hashes only. A status reader never writes this witness or
 * claims resources. Every legal B selfwrite is exact serializer + raw material
 * lineage, and an unrelated whitespace/unknown-field edit stays unavailable. */
export function onboard_witness(initial,current,authority,verify) {
 if(type(verify.digest)!='function')return null;
 let hash=value=>raw_hash(verify,value),base=authority?.base,cp=authority?.approval;
 if(authority?.permit)return clone(authority.permit);
 if(authority?.standby)return {schema:1,origin_tag:initial.tag,key:hash(initial.key),join_ca:hash(current.join_ca),
  network_ca:hash(initial.network_ca),cert:hash(initial.cert),requesting:null,pending:null,ap:hash(current.raw_identity || sprintf('%J',current.identity)),
  approved_ca:hash(initial.network_ca),approved_cert:hash(initial.cert),code:clone(initial.code),standby:clone(authority.standby)};
 let handoff=cp?.handoff || authority?.handoff;
 let value={schema:1,origin_tag:initial.tag,key:hash(initial.key),join_ca:hash(current.join_ca),
  network_ca:cp ? cp.before_ca : hash(initial.network_ca),cert:cp ? cp.before_cert : hash(initial.cert),
  requesting:base ? hash(pending_raw(base,'requesting')) : null,
  pending:base ? hash(pending_raw(base,'pending')) : null,
  ap:base ? hash(sprintf('%J',expected_ap(base,handoff))) : handoff ? hash(initial.raw_identity) : null,
  approved_ca:base ? hash(base.joining.invitation.ca) : handoff ? hash(initial.network_ca) : null,
  approved_cert:cp ? hash(cp.cert) : handoff ? hash(initial.cert) : null,code:clone(initial.code)};
 if(handoff)value.handoff=clone(handoff);
 return value;
}
function observation_authorized(value,scope,verify) {
 let w=value?.authority;
 if(value?.resources_verified!==true || value.error!=null || type(w)!='object' || w.schema!=1 ||
  !equal(sort(keys(w)),sort(w.standby!=null ? [...WITNESS,'standby'] : w.handoff!=null ? [...WITNESS,'handoff'] : WITNESS)) ||
  value.session_scope_tag!==w.origin_tag || value.boot!==scope?.boot || type(verify.digest)!='function')return false;
 function hash(raw){return raw_hash(verify,raw);}
 if(hash(scope.key)!==w.key || hash(scope.join_ca)!==w.join_ca)return false;
 let identity;try{identity=json(scope.identity);}catch(e){return false;}
 if(identity.role=='ap')return (w.handoff!=null ? verify.handoff_transport?.(scope,w.handoff)===true : hash(scope.identity)===w.ap) &&
  hash(scope.network_ca)===w.approved_ca && hash(scope.cert)===w.approved_cert &&
  verify.ca(scope.network_ca,w.code.fingerprint) && verify.leaf(scope.network_ca,scope.cert,scope.key,identity.id);
 if(identity.role!='unbound' || identity.binding || index(['requesting','pending'],identity.joining?.status)<0)return false;
 let checkpoint=identity.joining.approval,approved=checkpoint!=null ? checkpoint.handoff!=null ?
  verify.transport_approval?.(scope,checkpoint,null,w.handoff) : verify.approval?.(scope,checkpoint) : null;
 if(checkpoint!=null && !approved)return false;
 let original=approved?.base_identity || scope.identity,expected=identity.joining.status=='requesting' ? w.requesting : w.pending;
 if(!expected || hash(original)!==expected)return false;
 if(approved)return hash(approved.ca)===w.approved_ca && hash(approved.cert)===w.approved_cert &&
  checkpoint.before_ca===w.network_ca && checkpoint.before_cert===w.cert;
 return hash(scope.network_ca)===w.network_ca && hash(scope.cert)===w.cert;
}

export function onboard_observation_authorized(value,scope,verify) {
 try{return observation_authorized(value,scope,verify);}catch(e){return false;}
}
export function onboard_permit_frame(value,scope,checkpoint,expected,verify) {
 let identity=json(scope.identity),base=clone(identity);delete base.joining.approval;
 let with_checkpoint=clone(base);with_checkpoint.joining.approval=clone(checkpoint);
 let approved=verify.approval({...scope,identity:sprintf('%J',with_checkpoint)},checkpoint);
 if(!approved || approved.expected_identity!==expected || !value?.generation || !value.session_scope_tag)return null;
 let initial={...scope,identity:base,raw_identity:sprintf('%J',base),code:{address:base.joining.invitation.address,
  fingerprint:base.joining.invitation.fingerprint,token:base.joining.invitation.token},tag:value.session_scope_tag};
 let authority={base,approval:checkpoint},witness=onboard_witness(initial,initial,authority,verify);
 let frame={schema:1,generation:value.generation,boot:value.boot,origin_tag:value.session_scope_tag,
  before_tag:scope.tag,authority:witness};
 frame.proof=proof_hash(verify,'mesh-manager-onboard-permit-v1\n'+scope.key,sprintf('%J',canonical(frame)));
 return frame;
}
export function onboard_arm(initial,current,seen,value,frame,verify) {
 if(type(frame)!='object' || !equal(sort(keys(frame)),sort(['schema','generation','boot','origin_tag','before_tag','authority','proof'])) ||
  frame.schema!=1 || frame.generation!==value.generation || frame.boot!==initial.boot ||
  frame.origin_tag!==initial.tag || frame.before_tag!==current.tag || type(verify.hmac)!='function' ||
  type(verify.digest)!='function' || type(frame.authority)!='object')return null;
 let unsigned=clone(frame);delete unsigned.proof;
 if(type(frame.proof)!='string' || !match(frame.proof,/^[0-9a-f]{64}$/) ||
  frame.proof!==proof_hash(verify,'mesh-manager-onboard-permit-v1\n'+current.key,sprintf('%J',canonical(unsigned))))return null;
 let authority=onboard_authority(initial,current,seen,verify);if(!authority?.base)return null;
 let expected=onboard_witness(initial,current,authority,verify),w=frame.authority;
 for(let field in ['schema','origin_tag','key','join_ca','requesting','pending','approved_ca','code'])
  if(!equal(w[field],expected[field]))return null;
 if(w.handoff!=null) {
  if(!handoff_permit_valid(authority.base,current,w,verify) || w.ap!==raw_hash(verify,sprintf('%J',expected_ap(authority.base,w.handoff))))return null;
 }else if(w.ap!==expected.ap)return null;
 if(w.network_ca!== (authority.approval ? authority.approval.before_ca : current.network_ca==null ? null : raw_hash(verify,current.network_ca)) ||
  w.cert!== (authority.approval ? authority.approval.before_cert : current.cert==null ? null : raw_hash(verify,current.cert)) ||
  !match(w.approved_cert || '',/^[0-9a-f]{64}$/) ||
  !equal(sort(keys(w)),sort(w.handoff!=null ? [...WITNESS,'handoff'] : WITNESS)))return null;
 if(seen?.permit && !equal(seen.permit,w))return null;
 return {...authority,permit:clone(w)};
}
