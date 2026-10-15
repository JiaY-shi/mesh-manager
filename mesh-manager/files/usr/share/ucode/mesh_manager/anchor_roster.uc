// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import {clone,equal} from './model.uc';
import {valid_anchor} from './authority.uc';
import {migration_id,migration_hash} from './migration_model.uc';

export function anchor_roster(root,state,recipient,own_certificate) {
 if(root?.role!='root' || !valid_anchor(root.anchor) || recipient!=root.anchor.id || recipient==root.id)return null;
 let members=[{id:root.id,certificate:own_certificate}];
 for(let id in keys(state.members)) {
  let member=state.members[id];if(id!=recipient && member.authorized===true)push(members,{id,certificate:member.certificate,
   ...(member.certificate_successor ? {certificate_successor:member.certificate_successor} : {})});
 }
 return {schema:1,network_id:root.network_id,epoch:root.authority_epoch,controller_id:root.id,members};
}
// Called only with data from a verified, pinned and fresh signed response.
// The roster grants the retained gateway native path probes, never authority.
export function accept_anchor_roster(identity,cluster,roster) {
 if(identity?.role!='ap' || !valid_anchor(identity.anchor) || identity.anchor.id!=identity.id ||
  type(roster)!='object' || length(keys(roster))!=5 || roster.schema!==1 ||
  roster.network_id!==identity.binding?.network_id || roster.controller_id!==identity.binding.controller_id ||
  roster.epoch!==identity.authority_epoch || type(roster.members)!='array' || length(roster.members)>64)
  die('migration_conflict: Gateway probe roster must match the active controller binding');
 let members={},seen=[];
 for(let row in roster.members) {
  if(type(row)!='object' || length(keys(row))!=(row.certificate_successor ? 3 : 2) ||
   row.certificate_successor!=null && !migration_hash(row.certificate_successor) || !migration_id(row.id) || !migration_hash(row.certificate) ||
   row.id==identity.id || index(seen,row.id)>=0)die('migration_conflict: Invalid gateway probe roster');
  push(seen,row.id);members[row.id]={id:row.id,certificate:row.certificate,authorized:true,
   ...(row.certificate_successor ? {certificate_successor:row.certificate_successor} : {})};
 }
 if(members[identity.binding.controller_id]?.certificate!==identity.binding.controller_certificate)
  die('migration_conflict: Gateway roster must retain the pinned active controller');
 let current=map(sort(keys(cluster.members || {})),id=>({id,certificate:cluster.members[id].certificate,authorized:cluster.members[id].authorized,
   ...(cluster.members[id].certificate_successor ? {certificate_successor:cluster.members[id].certificate_successor} : {})})),
  desired=map(sort(keys(members)),id=>members[id]);
 if(equal(current,desired) && equal(cluster.roster_authority,identity.binding))return false;
 cluster.members=members;cluster.roster_authority=clone(identity.binding);return true;
}
