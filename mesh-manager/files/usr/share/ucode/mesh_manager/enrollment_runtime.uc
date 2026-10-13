// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as native from 'mesh_enrollment_runtime';
import * as crypto from 'mesh_crypto';
import * as durable from './durable.uc';
import { equal } from './model.uc';
import { enrollment_progress, project_enrollment } from './enrollment_progress.uc';

const observation={read:native.read,now:native.now,alive:native.alive,hmac:crypto.hmac};
export function enrollment_uptime() { return native.now(); }
export function enrollment_observation(identity,boot,now) {
 return project_enrollment(identity,boot,now,observation);
}
export function enrollment_runtime(io,storage) {
 io=io || durable;storage=storage || native;
 const progress=enrollment_progress({identity:()=>io.load('identity.json'),boot:io.boot,
  now:storage.now,owner:storage.owner,random:io.random,read:storage.read,publish:storage.publish,
  alive:storage.alive,hmac:crypto.hmac});
 let backoff=0;
 const checked={
  begin:data=>io.locked(()=>equal(data,io.load('identity.json')) ? progress.begin(data) : null),
  check:frame=>io.locked(()=>progress.check(frame)),
  commit:(frame,patch)=>io.locked(()=>progress.commit(frame,patch))
 };
 function boundary(expected,callback) {
  return io.locked(()=>{
   let data=io.load('identity.json');
   if(!equal(data,expected))return false;
   let before=sprintf('%J',data);callback(data);
   if(sprintf('%J',data)!=before)io.save('identity.json',data);
   return true;
  });
 }
 return {progress:checked,boundary,
  run:callback=>{
   if(progress.lost())return false;
   let now=storage.now();if(now<backoff)return true;
   try{callback();backoff=0;}catch(e){backoff=storage.now()+30000;}
   return !progress.lost();
  },
  // The caller already owns the cluster lock here. Network operations must not
  // run inside it; certificates/requests use the original durable writer.
  check_locked:frame=>progress.check(frame),
  project:identity=>project_enrollment(identity,io.boot(),storage.now(),{...storage,hmac:crypto.hmac})};
}
