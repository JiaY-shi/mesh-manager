// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as crypto from 'mesh_crypto';
import {equal} from './model.uc';
import {authority_busy} from './authority.uc';
import {migration_budget as resource_budget} from './migration_budget.uc';

// Ordinary authenticated polls carry renewal requests and their exact replies.
// Only the local certificate replacement needs a recovery record; there is no
// network-wide operation, approval, deadline or barrier between APs.
export function certificate_renewal(io) {
 let budget=io.budget || resource_budget, clock=io.time || time;
 let expiry;
 function scope(i) {return [i.id,i.role,i.network_id,i.binding?.controller_id,i.authority_epoch || 1];}
 function valid(cert,i) {return type(cert)=='string' && length(cert)<=8192 &&
  crypto.verify_leaf(io.read('network-ca.crt'),cert,io.read('device.key'),i.id);}
 function due(cert,id) {
  let now=clock(),ca=io.read('network-ca.crt');
  if(expiry?.cert==cert && expiry.ca==ca && now>=expiry.checked && now<expiry.checked+3600)return expiry.due;
  let status=crypto.certificate_status(ca,cert,id,now);
  expiry={cert,ca,checked:now,due:status.ca.status=='valid' && status.device.status=='expiring'};
  return expiry.due;
 }
 function save(name,value) {io.write_cas(name,io.read(name),sprintf('%J',value),5000);}
 function recover() {
  let i=io.load('identity.json'),j=i?.certificate_update;
  if(!j)return false;
  budget(length(sprintf('%J',j)));
  if(type(j)!='object' || length(keys(j))!=4 || !equal(j.scope,scope(i)) ||
   j.ca!=crypto.fingerprint(io.read('network-ca.crt')) || !valid(j.next,i) ||
   crypto.certificate_key_fingerprint(j.before)!=i.fingerprint)
   die('certificate_conflict: Certificate recovery no longer matches this identity');
  let current=io.read('device.crt');
  if(current!==j.next)io.write_cas('device.crt',j.before,j.next,5000);
  if(i.anchor?.id==i.id)i.anchor.certificate=crypto.fingerprint(j.next);
  delete i.certificate_update;delete i.certificate_requested;
  save('identity.json',i);return true;
 }
 function install(next) {
  recover();let i=io.load('identity.json'),before=io.read('device.crt');
  if(next===before)return;
  if(authority_busy(i,i.role=='root' ? io.load('cluster.json') : null) || !valid(next,i))
   die('certificate_conflict: Certificate replacement requires the active identity and authority');
  budget(length(before)+length(next));
  i.certificate_update={before,next,ca:crypto.fingerprint(io.read('network-ca.crt')),scope:scope(i)};
  save('identity.json',i);recover();
 }
 function request(node_id) {
  let i=io.load('identity.json'),s=io.load('cluster.json');
  if(i?.role!='root')die('not_controller: Only the controller can request certificate renewal');
  if(authority_busy(i,s))die('migration_pending: Finish controller migration before renewing certificates');
  if(node_id && node_id!=i.id && s.members[node_id]?.authorized!==true)
   die('not_authorized: Certificate renewal requires an authorized device');
  budget(0);let requested=[];
  for(let id in keys(s.members))if((!node_id || node_id==id) && s.members[id].authorized===true) {
   s.members[id].certificate_requested=true;push(requested,id);
  }
  if(length(requested))save('cluster.json',s);
  if(!node_id || node_id==i.id){i.certificate_requested=true;save('identity.json',i);push(requested,i.id);}
  return {requested};
 }
 function root_tick() {
  recover();let i=io.load('identity.json'),s=io.load('cluster.json');
  if(i?.role!='root' || authority_busy(i,s) || !i.certificate_requested && !due(io.read('device.crt'),i.id))return;
  // A legacy peer must learn the stable key through its original exact leaf
  // pin first. Other peers' independent renewals never wait for this upgrade.
  for(let m in values(s.members))if(m.authorized===true && m.controller_key!==i.fingerprint)return;
  let next=crypto.sign(io.read('network-ca.key'),io.read('network-ca.crt'),crypto.csr(io.read('device.key'),i.id),i.id);
  if(!next)die('certificate_error: Cannot issue the controller certificate');
  install(next);
 }
 function peer(id,presented,credentials) {
  if(credentials==null)return null;
  if(type(credentials)!='object' || length(sprintf('%J',credentials))>16384)
   die('invalid_request: Invalid certificate renewal request');
  let i=io.load('identity.json'),s=io.load('cluster.json'),m=s.members[id],changed=false;
  if(i.role!='root' || m?.authorized!==true || presented!=m.certificate && presented!=m.certificate_successor)
   die('not_authorized: Certificate is no longer authorized');
  if(presented==m.certificate_successor) {
   m.certificate=presented;delete m.certificate_successor;delete m.certificate_offer;
   delete m.certificate_requested;changed=true;
   if(i.anchor?.id==id){i.anchor.certificate=presented;save('identity.json',i);}
  }
  if(credentials.certificate!=null) {
   let cert=credentials.certificate,key=crypto.certificate_key_fingerprint(cert),
    status=crypto.certificate_status(io.read('network-ca.crt'),cert,id,clock()).device;
   if(crypto.fingerprint(cert)!=presented || crypto.certificate_identity(cert)!=id ||
    index(['valid','expiring'],status.status)<0 || !key || m.public_key && m.public_key!=key)
    die('certificate_error: Public certificate does not match the authenticated peer');
   if(m.public_key!=key){m.public_key=key;changed=true;}
   if(m.certificate_expires_at!=status.expires_at){m.certificate_expires_at=status.expires_at;changed=true;}
  }
  let own=io.read('device.crt'),out={};
  if(credentials.certificate!=null)out.accepted=presented;
  if(credentials.controller_key==i.fingerprint && m.controller_key!==i.fingerprint) {
   m.controller_key=i.fingerprint;changed=true;
  }
  if(credentials.controller!=crypto.fingerprint(own) || credentials.controller_key!=i.fingerprint)out.controller=own;
  let gateway=i.anchor?.id==i.id ? i.fingerprint : s.members[i.anchor?.id]?.public_key;
  if(gateway && credentials.gateway_key!=gateway)out.gateway_key=gateway;
  if(i.anchor && credentials.gateway_certificate!=i.anchor.certificate)out.gateway_certificate=i.anchor.certificate;
  if(!m.public_key)out.need_certificate=true;
  if(!authority_busy(i,s)) {
   if(credentials.csr!=null && !m.certificate_offer && m.public_key) {
    if(!m.certificate_requested && !(m.certificate_expires_at>clock() && m.certificate_expires_at<=clock()+30*86400))
     die('certificate_not_due: Device certificate does not need renewal');
    if(type(credentials.csr)!='string' || length(credentials.csr)>8192 || !m.public_key)
     die('certificate_error: Invalid device certificate request');
    budget(length(credentials.csr));
    let next=crypto.sign(io.read('network-ca.key'),io.read('network-ca.crt'),credentials.csr,id);
    if(!next || crypto.certificate_key_fingerprint(next)!=m.public_key)
     die('certificate_error: Certificate request changed the device key');
    m.certificate_offer=next;m.certificate_successor=crypto.fingerprint(next);changed=true;
   }
   if(m.certificate_offer)out.install={before:m.certificate,certificate:m.certificate_offer};
   else if(m.certificate_requested)out.renew=true;
  }
  if(changed){budget(length(sprintf('%J',out)));save('cluster.json',s);}
  return length(keys(out)) ? out : null;
 }
 let acknowledged,renew=false,need_certificate=false;
 function poll(i) {
  let cert=io.read('device.crt'),fingerprint=crypto.fingerprint(cert);
  return {controller:i.binding.controller_certificate,controller_key:i.binding.controller_key || null,
   gateway_key:i.gateway_key || null,gateway_certificate:i.anchor?.certificate || null,
   ...(acknowledged!=fingerprint || need_certificate ? {certificate:cert} : {}),
   ...(renew || due(cert,i.id) ? {csr:crypto.csr(io.read('device.key'),i.id)} : {})};
 }
 // Called under the cluster lock, only after verification of the signed reply.
 function accept(captured,reply) {
  if(reply==null)return;
  let i=io.load('identity.json');
  if(i?.role!='ap' || !equal(captured.binding,i.binding) || captured.id!=i.id)
   die('identity_error: AP binding changed before certificate renewal');
  let changed=false;
  if(reply.controller!=null) {
   let cert=reply.controller,key=crypto.certificate_key_fingerprint(cert),status=
    crypto.certificate_status(io.read('network-ca.crt'),cert,i.binding.controller_id,clock()).device.status;
   if(crypto.certificate_identity(cert)!=i.binding.controller_id || index(['valid','expiring'],status)<0 ||
    (i.binding.controller_key ? key!=i.binding.controller_key : crypto.fingerprint(cert)!=i.binding.controller_certificate))
    die('certificate_error: Controller renewal changed the pinned identity');
   if(i.binding.controller_certificate!=crypto.fingerprint(cert) || i.binding.controller_key!=key) {
    i.binding.controller_certificate=crypto.fingerprint(cert);i.binding.controller_key=key;changed=true;
   }
  }
  // The original pin can also be learned when the certificate is unchanged.
  if(reply.gateway_key!=null && (!match(reply.gateway_key,/^[0-9a-f]{64}$/) || length(reply.gateway_key)!=64 ||
   substr(reply.gateway_key,0,32)!=i.anchor?.id))
   die('certificate_error: Invalid gateway key pin');
  if(reply.gateway_key && i.gateway_key!=reply.gateway_key){i.gateway_key=reply.gateway_key;changed=true;}
  if(reply.gateway_certificate!=null) {
   if(!match(reply.gateway_certificate,/^[0-9a-f]{64}$/) || length(reply.gateway_certificate)!=64 || !i.anchor)
    die('certificate_error: Invalid gateway certificate pin');
   if(i.anchor.certificate!=reply.gateway_certificate){i.anchor.certificate=reply.gateway_certificate;changed=true;}
  }
  if(changed)save('identity.json',i);
  acknowledged=reply.accepted;need_certificate=reply.need_certificate===true;renew=reply.renew===true;
  if(reply.install!=null) {
   if(reply.install.before!=crypto.fingerprint(io.read('device.crt')) &&
    reply.install.certificate!==io.read('device.crt'))die('certificate_conflict: Stale certificate offer');
   install(reply.install.certificate);renew=false;
  }
 }
 return {recover,install,request,root_tick,peer,poll,accept};
}
