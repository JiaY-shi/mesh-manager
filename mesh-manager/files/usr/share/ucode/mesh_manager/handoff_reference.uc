// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as crypto from 'mesh_crypto';
import { clone, equal, canonical, valid_text } from './model.uc';
import { private_address } from './identity.uc';
import { initial } from './transaction.uc';

const LIMIT=4096;
const REF=['schema','request','joining','epoch','identity','key','ca','cert','journal','journal_base','snapshot','proof'];
export function hex(v,n){return type(v)=='string' && length(v)==n && match(v,/^[0-9a-f]+$/)!=null;}
export function integer(v,min,max){return type(v)=='int' && v>=min && v<=max;}
export function hash(v){
 if(v==null)return null;
 if(type(v)!='string')die('handoff_conflict: Raw handoff digest input is invalid');
 let h=crypto.sha256(v);if(!hex(h,64))die('handoff_conflict: Handoff digest unavailable');return h;
}
export function raw(v){return sprintf('%J',v);}
export function object(text){if(type(text)!='string')die('handoff_conflict: Raw object unavailable');let v=json(text);if(type(v)!='object' || raw(v)!==text)die('handoff_conflict: Raw object changed');return v;}
export function exact(v,fields){return type(v)=='object' && equal(sort(keys(v)),sort(fields));}
export function sign(v,key,domain){let r=clone(v);delete r.proof;let proof=crypto.hmac(hash('mesh-manager/first-handoff/'+domain+'/v1\n'+key),raw(canonical(r)));
 if(!hex(proof,64))die('handoff_conflict: Handoff proof unavailable');return proof;}
export function sealed(v,key,domain,fields){return exact(v,fields) && length(raw(v))<=LIMIT && hex(v.proof,64) && crypto.constant_equal(v.proof,sign(v,key,domain));}
export function bare(data){let v=clone(data);delete v.handoff;delete v.agent;delete v.cluster_version;return v;}
function code(value){let p=type(value)=='string'?split(value,':'):[];if(length(p)!=4 || p[0]!='MM1' || !private_address(p[1]) || !hex(p[2],64) || !hex(p[3],64))die('handoff_conflict: Original controller code unavailable');return {address:p[1],fingerprint:p[2],token:p[3]};}
function consent(data){let e=data?.enrollment;return e?.enabled===true && hex(e.epoch,32) && valid_text(e.ssid,1,32) && type(e.password)=='string' && length(e.password)>=8 && length(e.password)<=63 && type(e.code)=='string';}
export function journal(text){return text==null ? initial() : object(text);}
export function pristine(j){return j.schema===1 && j.version===0 && j.paused===false && j.intent==null && j.saved_intent==null &&
 type(j.owned)=='array' && !length(j.owned) && type(j.history)=='array' && !length(j.history) && j.active==null && j.restore_checkpoint==null && j.first_handoff==null;}
export function base_journal(j){let v=clone(j);delete v.first_handoff;v.version=0;v.intent=null;v.saved_intent=null;v.owned=[];v.history=[];v.active=null;return raw(v);}
export function scope_valid(scope){
 if(type(scope)!='object' || type(scope.key)!='string' || type(scope.network_ca)!='string' || type(scope.cert)!='string')die('handoff_conflict: Original credentials unavailable');
 let data=object(scope.identity),f=crypto.key_fingerprint(scope.key),binding=data.binding,pin=code(data.enrollment?.code);
 if(data.schema!==1 || data.role!='ap' || data.joining!=null || !hex(f,64) || data.id!=substr(f,0,32) || data.fingerprint!=f || !consent(data) ||
  !exact(binding,['address','controller_id','network_id','port','ca_fingerprint']) || !hex(binding.controller_id,32) || !hex(binding.network_id,32) ||
  binding.address!=pin.address || binding.ca_fingerprint!=pin.fingerprint || binding.port!=37901 || data.network_id!=binding.network_id ||
  scope.join_ca!==scope.network_ca || crypto.fingerprint(scope.network_ca)!=pin.fingerprint || crypto.normalize_cert(scope.network_ca)!==scope.network_ca ||
  !crypto.verify_leaf(scope.network_ca,scope.cert,scope.key,data.id))die('handoff_conflict: Original AP identity or consent changed');
 return data;
}
export function authority(scope){let data=scope_valid(scope),r=data.handoff;
 if(!sealed(r,scope.key,'identity',REF) || r.schema!==1 || !hex(r.request,32) || !hex(r.joining,64) || !hex(r.epoch,32) || r.epoch!==data.enrollment.epoch ||
  r.identity!==hash(raw(bare(data))) || r.key!==hash(scope.key) || r.ca!==hash(scope.network_ca) || r.cert!==hash(scope.cert) ||
  !hex(r.journal_base,64) || !hex(r.snapshot,64) || r.journal!=null && !hex(r.journal,64))die('handoff_conflict: Original handoff reference changed');
 return {data,ref:r};
}

// Returned identity belongs in the original final approval save, never a later
// marker write. It is a candidate, not a durable or network effect.
export function reference_prepare(before,approved,journal_raw,snapshot_raw){
 let original=object(before?.identity),data=scope_valid(approved),j=original.joining,v=j?.invitation,baseline=journal(journal_raw);
 if(original.schema!==1 || original.role!='unbound' || original.binding || !consent(original) || index(['requesting','pending'],j?.status)<0 ||
  !hex(j.request_id,32) || !hex(j.secret,64) || original.id!=data.id || before.key!==approved.key || before.join_ca!==approved.network_ca ||
  v?.ca!==approved.network_ca || v.controller_id!==data.binding.controller_id || v.network_id!==data.binding.network_id ||
  v.address!==data.binding.address || v.fingerprint!==data.binding.ca_fingerprint || !pristine(baseline) || original.handoff!=null || data.handoff!=null ||
  original.agent!=null || data.agent!=null || original.cluster_version!=null && original.cluster_version!==0 || data.cluster_version!=null && data.cluster_version!==0)
  die('handoff_conflict: Only original initial automatic approval may create a handoff');
 let expected=clone(original);expected.binding=clone(data.binding);expected.network_id=data.network_id;expected.role='ap';expected.joining=null;
 if(!equal(expected,data))die('handoff_conflict: Approval changed unrelated original identity');
 object(snapshot_raw);
 let ref={schema:1,request:j.request_id,joining:hash(raw(j)),epoch:data.enrollment.epoch,identity:hash(raw(bare(data))),
  key:hash(approved.key),ca:hash(approved.network_ca),cert:hash(approved.cert),journal:hash(journal_raw),
  journal_base:hash(base_journal(baseline)),snapshot:hash(snapshot_raw)};
 ref.proof=sign(ref,approved.key,'identity');data.handoff=ref;
 return {identity:raw(data),ref:clone(ref)};
}

// Called only after the original joining checkpoint's complete HMAC/identity/
// CA/leaf checks. It derives the one proposed AP from exact pre-checkpoint raw,
// and requires the captured full initial journal and UCI snapshot again.
export function reference_approval(scope,checkpoint,original){
 try{
  if(type(scope)!='object' || !('state' in scope) || type(scope.snapshot)!='string' || checkpoint?.handoff==null)return null;
  let before={...scope,identity:original},data=object(original),v=data.joining.invitation,ap=clone(data);
  ap.binding={address:v.address,controller_id:v.controller_id,network_id:v.network_id,port:v.port,ca_fingerprint:v.fingerprint};
  ap.network_id=v.network_id;ap.role='ap';ap.joining=null;
  let approved={...scope,identity:raw(ap),network_ca:v.ca,cert:checkpoint.cert};
  let expected=reference_prepare(before,approved,scope.state,scope.snapshot);
  return equal(expected.ref,checkpoint.handoff)?expected:null;
 }catch(e){return null;}
}

// Only an already-authorized actor may supply this exact reference from its
// one-permit witness. This does not authorize cold AP startup or a new baseline.
export function reference_transport(scope,checkpoint,original,permitted_ref){
 try{
  if(checkpoint?.handoff==null || !equal(checkpoint.handoff,permitted_ref))return null;
  let before=object(original),j=before.joining,v=j?.invitation,ap=clone(before);
  if(before.role!='unbound' || before.binding || before.handoff!=null || before.agent!=null ||
   before.cluster_version!=null && before.cluster_version!==0 || !consent(before) ||
   index(['requesting','pending'],j?.status)<0 || j.approval!=null || !hex(j.request_id,32) || !hex(j.secret,64))return null;
  ap.binding={address:v.address,controller_id:v.controller_id,network_id:v.network_id,port:v.port,ca_fingerprint:v.fingerprint};
  ap.network_id=v.network_id;ap.role='ap';ap.joining=null;ap.handoff=clone(checkpoint.handoff);
  let approved={...scope,identity:raw(ap),network_ca:v.ca,cert:checkpoint.cert},a=authority(approved);
  if(a.ref.request!==j.request_id || a.ref.joining!==hash(raw(j)))return null;
  return {identity:raw(ap),ref:clone(a.ref)};
 }catch(e){return null;}
}
