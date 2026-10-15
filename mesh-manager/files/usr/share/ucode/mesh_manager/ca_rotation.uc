// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as crypto from 'mesh_crypto';
import {equal} from './model.uc';
import {authority_busy} from './authority.uc';
import {migration_budget as resource_budget} from './migration_budget.uc';

export function ca_pending(s) {return s?.ca_rotation!=null && s.ca_rotation.phase!='complete';}
export function public_ca(s) {
 let r=s?.ca_rotation;return r ? {id:r.id,phase:r.phase,ca:r.ca || crypto.fingerprint(r.next)} : null;
}
// One manual operation on the existing authenticated poll. The only barrier is
// trust before issuance, then proof of new leaves before retiring old trust.
export function ca_rotation(io) {
 let budget=io.budget || resource_budget;
 function save(n,v) {io.write_cas(n,io.read(n),sprintf('%J',v),5000);}
 function scope(i) {return [i.id,i.role,i.network_id,i.binding?.controller_id,i.authority_epoch || 1];}
 function healthy(ca) {return type(ca)=='string' && length(ca)<8192 &&
  index(['valid','expiring'],crypto.certificate_status(ca,null,null,time()).ca.status)>=0;}
 function recover() {
  let i=io.load('identity.json'),j=i?.ca_update;if(!j)return false;
  budget(length(sprintf('%J',j)));
  if(type(j)!='object' || length(keys(j))!=6 || !equal(j.scope,scope(i)) || !healthy(j.next) ||
   !crypto.verify_leaf(j.next,io.read('device.crt'),io.read('device.key'),i.id) ||
   j.key!=null && (i.role!='root' || crypto.key_fingerprint(j.key)!=crypto.certificate_key_fingerprint(j.next)))
   die('ca_conflict: CA replacement no longer matches the active identity');
  let ca=io.read('network-ca.crt'),key=io.read('network-ca.key');
  if(ca!==j.before && ca!==j.next || j.key!=null &&
   crypto.sha256(key)!=j.before_key && key!==j.key)
   die('ca_conflict: CA material changed outside this replacement');
  if(j.key!=null && key!==j.key)io.write_cas('network-ca.key',key,j.key,5000);
  if(ca!==j.next)io.write_cas('network-ca.crt',j.before,j.next,5000);
  i.ca_fingerprint=crypto.fingerprint(j.next);
  if(i.role=='ap') {
   i.binding.ca_fingerprint=i.ca_fingerprint;
   if(j.rotation)i.ca_rotation={id:j.rotation};else delete i.ca_rotation;
  }
  delete i.ca_update;save('identity.json',i);return true;
 }
 function install(next,key,rotation) {
  recover();let i=io.load('identity.json'),before=io.read('network-ca.crt');
  if(i.certificate_update || authority_busy(i,i.role=='root' ? io.load('cluster.json') : null))
   die('ca_pending: Finish local certificate recovery or controller migration first');
  if(!healthy(next) || !crypto.verify_leaf(next,io.read('device.crt'),io.read('device.key'),i.id))
   die('ca_conflict: CA replacement must retain trust in the active device certificate');
  if(before===next && (key==null || key===io.read('network-ca.key'))) {
   if(i.role=='ap' && (i.ca_rotation?.id || null)!==(rotation || null)) {
    if(rotation)i.ca_rotation={id:rotation};else delete i.ca_rotation;budget(256);save('identity.json',i);
   }
   return;
  }
  budget(length(before)+length(next));
  i.ca_update={scope:scope(i),before,next,key:key || null,
   before_key:key ? crypto.sha256(io.read('network-ca.key')) : null,rotation:rotation || null};
  save('identity.json',i);recover();
 }
 function start(expected,id) {
  let i=io.load('identity.json');if(i?.role!='root')die('not_controller: Only the controller can rotate the network CA');
  let s=io.load('cluster.json'),r=s.ca_rotation;
  if(!match(id || '',/^[0-9a-f]{32}$/) || length(id)!=32)
   die('invalid_request: CA rotation requires a request ID');
  if(r?.id==id)return public_ca(s);
  let before=io.read('network-ca.crt');
  if(ca_pending(s) || i.ca_update || i.certificate_update || i.certificate_requested || authority_busy(i,s) ||
   length(filter([s.active,s.lifecycle],j=>j && index(['complete','partial','failed','rolled_back','cancelled','expired'],j.phase)<0)) ||
   length(filter(values(s.requests || {}),r=>r.status=='pending')) ||
   length(filter(values(s.members),m=>m.authorized && (m.certificate_offer || m.certificate_requested ||
    m.repair && index(['committed','failed','rolled_back','expired','cancelled'],m.repair.status)<0))))
   die('ca_pending: Finish the current network or credential operation first');
  if(expected!=crypto.fingerprint(before) || before!==crypto.normalize_cert(before) || !healthy(before))
   die('ca_changed: Refresh the current CA before rotating it');
  budget(16384);let key=crypto.keypair(),next=key ? crypto.ca(key,i.id) : null;
  if(!next)die('ca_error: Cannot generate the next network CA');
  s.ca_rotation={id,phase:'trust',before,next,key};save('cluster.json',s);return public_ca(s);
 }
 function desired(r) {return r.phase=='trust' ? r.before+r.next : r.phase=='renew' ? r.next+r.before : r.next;}
 function tick() {
  recover();let i=io.load('identity.json');if(i?.role!='root')return;
  let s=io.load('cluster.json'),r=s.ca_rotation;if(!ca_pending(s))return;
  if(authority_busy(i,s) || i.certificate_update)return;
  let members=filter(values(s.members),m=>m.authorized===true),bundle=desired(r),fp=crypto.fingerprint(r.next);
  install(bundle,r.phase=='renew' ? r.key : null,null);
  if(length(filter(members,m=>m.ca_bundle!=crypto.sha256(bundle))))return;
  if(r.phase=='trust') {
   // Persist the phase before replacing the issuer. A cold worker finishes
   // this exact transition using the existing CA journal before issuing leaves.
   r.phase='renew';save('cluster.json',s);return;
  }
  if(r.phase=='renew') {
   if(r.key) {
    delete r.key;
    for(let m in members)m.certificate_requested=true;
    save('cluster.json',s);i=io.load('identity.json');i.certificate_requested=true;save('identity.json',i);return;
   }
   // Retry by actual leaves, including an old-issuer offer that completed
   // during trust distribution or a cut between the request writes.
   let changed=false;
   for(let m in members)if(m.certificate_ca!=fp && !m.certificate_requested) {m.certificate_requested=true;changed=true;}
   if(changed)save('cluster.json',s);
   if(!crypto.verify_leaf(r.next,io.read('device.crt'),io.read('device.key'),i.id)) {
    if(!i.certificate_requested){i.certificate_requested=true;save('identity.json',i);}return;
   }
   if(length(filter(members,m=>m.certificate_ca!=fp)))return;
   r.phase='retire';save('cluster.json',s);return;
  }
  s.ca_rotation={id:r.id,phase:'complete',ca:fp};save('cluster.json',s);
 }
 function poll(i) {return {bundle:crypto.sha256(io.read('network-ca.crt')),rotation:i.ca_rotation?.id || null};}
 function peer(id,request) {
  if(type(request)!='object' || length(sprintf('%J',request))>256)return null;
  let s=io.load('cluster.json'),r=s.ca_rotation,m=s.members[id];if(!r || !m?.authorized)return null;
  if(r.phase=='complete')return request.rotation ? {id:r.id,phase:'complete',before:request.bundle,bundle:io.read('network-ca.crt')} : null;
  let allowed=[r.before,r.before+r.next,r.next+r.before,r.next];
  if(index(map(allowed,crypto.sha256),request.bundle)<0)die('ca_conflict: Peer trust differs from this CA rotation');
  if(m.ca_bundle!=request.bundle){budget(256);m.ca_bundle=request.bundle;save('cluster.json',s);}
  let bundle=desired(r);
  return request.bundle!=crypto.sha256(bundle) || request.rotation!=r.id ?
   {id:r.id,phase:r.phase,before:request.bundle,bundle} : null;
 }
 function accept(captured,reply) {
  if(reply==null)return;
  let i=io.load('identity.json');
  if(i?.role!='ap' || captured.id!=i.id || !equal(captured.binding,i.binding) ||
   type(reply)!='object' || length(keys(reply))!=4 ||
   !match(reply.id || '',/^[0-9a-f]{32}$/) || length(reply.id)!=32 ||
   index(['trust','renew','retire','complete'],reply.phase)<0 ||
   reply.before!=crypto.sha256(io.read('network-ca.crt')))
   die('ca_conflict: CA response no longer matches the authenticated AP binding');
  install(reply.bundle,null,reply.phase=='complete' ? null : reply.id);
 }
 return {recover,install,start,tick,poll,peer,accept};
}
