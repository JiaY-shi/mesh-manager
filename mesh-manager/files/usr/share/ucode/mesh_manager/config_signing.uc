// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as crypto from 'mesh_crypto';
import {equal} from './model.uc';
import {authority_busy} from './authority.uc';
import {migration_budget as resource_budget} from './migration_budget.uc';

export const SIGNER_DOMAIN='mesh-manager/config-key/v1\n';
export function signer_epoch(epoch) {return type(epoch)=='int' && epoch>=1 && epoch<=2147483646;}
export function signer_statement(network,id,epoch,key) {return SIGNER_DOMAIN+sprintf('%J',{network_id:network,controller_id:id,epoch,key});}
export function public_signer(state,network) {
 let s=state?.config_signing;if(!s)return null;
 let key=crypto.public_key(s.key);
 if(!signer_epoch(s.epoch) || !key)die('signing_error: Invalid configuration signing key');
 return {network_id:network,epoch:s.epoch,key};
}

// One private cluster field, one public AP pin. No additional certificates,
// scheduling process or key history. Call mutating functions under the lock.
export function config_signing(io) {
 let budget=io.budget || resource_budget;
 function save(name,before,value) {io.write_cas(name,before,sprintf('%J',value),5000);}
 function root() {
  let i=io.load('identity.json');
  if(i?.role!='root')die('not_controller: Only the controller can rotate configuration signing keys');
  let raw=io.read('cluster.json'),s=json(raw);
  if(authority_busy(i,s))die('migration_pending: Finish controller migration before rotating keys');
  return {i,raw,s};
 }
 function ensure() {
  let f=root();if(f.s.config_signing){public_signer(f.s,f.i.network_id);return;}
  budget(512);let key=crypto.keypair();if(!key)die('signing_error: Cannot generate configuration signing key');
  f.s.config_signing={epoch:1,key};save('cluster.json',f.raw,f.s);
 }
 function rotate(expected,id) {
  let f=root(),s=f.s.config_signing;
  if(!match(id || '',/^[0-9a-f]{32}$/) || length(id)!=32 || !signer_epoch(expected))
   die('invalid_request: Rotation requires the current signing epoch and request ID');
  public_signer(f.s,f.i.network_id);
  if(!s || s.epoch!=expected && s.request_id!=id)die('signing_changed: Refresh the current signing epoch');
  if(s.request_id==id)return {epoch:s.epoch};
  if(s.epoch>=2147483646)die('signing_limit: Configuration signing epoch is exhausted');
  budget(512);let key=crypto.keypair();if(!key)die('signing_error: Cannot generate configuration signing key');
  f.s.config_signing={epoch:s.epoch+1,key,request_id:id};save('cluster.json',f.raw,f.s);
  return {epoch:f.s.config_signing.epoch};
 }
 function accept(captured,pin) {
  if(!pin)return;
  let raw=io.read('identity.json'),i=json(raw);
  if(i?.role!='ap' || captured.id!=i.id || !equal(captured.binding,i.binding) ||
   pin.network_id!=i.binding.network_id || !signer_epoch(pin.epoch) || type(pin.key)!='string' || length(pin.key)>512)
   die('signing_error: Configuration signer does not match the active binding');
  let old=i.signing;
  if(old?.network_id==pin.network_id && (old.epoch>pin.epoch || old.epoch==pin.epoch && old.key!=pin.key))
   die('signing_error: Retired configuration signer cannot be restored');
  if(equal(old,pin))return;
  budget(512);i.signing=pin;save('identity.json',raw,i);
 }
 return {ensure,rotate,accept};
}
