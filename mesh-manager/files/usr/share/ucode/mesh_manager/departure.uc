// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as crypto from 'mesh_crypto';
import { clone, equal, canonical } from './model.uc';
import { initial } from './transaction.uc';

function digest(value) { return crypto.sha256(value); }
function proof(value,key) {
	let body=clone(value);delete body.proof;
	return crypto.hmac(crypto.sha256('mesh-manager/departure/key/v1\n'+key),
		'mesh-manager/departure/v1\n'+sprintf('%J',canonical(body)));
}
function fail() { die('departure_conflict: Restored configuration or original network binding changed'); }

// Only a freshly nonce-bound, signed Root response can begin departure. All
// writes use the original raw identity/journal and the existing two locks.
// The checkpoint permits replay after a crash between these durable writes.
export function departure_service(io) {
	function resume(receipt) {
		return io.with_local(() => {
			let raw=io.read('identity.json'),data=json(raw),key=io.read('device.key'),checkpoint=data.departing;
			if (data.role!='ap' || !data.binding || crypto.key_fingerprint(key)!=data.fingerprint) fail();
			if (!checkpoint) {
				let r=receipt?.authorization,tx=r?.restoration,b=data.binding;
				if (receipt?.controller_id!=b.controller_id || receipt.network_id!=b.network_id ||
					r?.status!='revoked' || r.node_id!=data.id ||
					r.certificate!=crypto.fingerprint(io.read('device.crt')) ||
					crypto.fingerprint(io.read('network-ca.crt'))!=b.ca_fingerprint ||
					type(r.removed)!='int' || r.removed<1704067200 ||
					type(tx)!='object' || length(keys(tx))!=4 || tx.version!==data.cluster_version) fail();
				let before=io.read('state.json'),record=io.verify(before,tx.transaction_id,tx.request_id);
				if (!record || record.version!==tx.local_version) fail();
				let journal=json(before),after=initial(),archives=journal.network_archive || [];
				if (type(archives)!='array' || length(archives)>4) fail();
				push(archives,{controller_id:b.controller_id,network_id:b.network_id,removed:r.removed,
					version:journal.version,history:map(journal.history,h=>({id:h.id,kind:h.kind,status:h.status,
						version:h.version,timestamp:h.timestamp}))});
				after.network_archive=slice(archives,-4);
				if (journal.local_settings) after.local_settings=clone(journal.local_settings);
				checkpoint={schema:1,identity:raw,before,after:sprintf('%J',after),
					snapshot:digest(sprintf('%J',canonical(io.snapshot()))),certificate:io.read('device.crt'),
					ca:io.read('network-ca.crt'),receipt:clone(receipt)};
				checkpoint.proof=proof(checkpoint,key);
				data.departing=checkpoint;
				io.replace('identity.json',raw,sprintf('%J',data));raw=sprintf('%J',data);
			}
			if (checkpoint.schema!==1 || !crypto.constant_equal(checkpoint.proof,proof(checkpoint,key)) ||
				io.read('device.crt')!==checkpoint.certificate || io.read('network-ca.crt')!==checkpoint.ca ||
				digest(sprintf('%J',canonical(io.snapshot())))!=checkpoint.snapshot) fail();
			let original=json(checkpoint.identity),expected=clone(original);expected.departing=clone(checkpoint);
			if (!equal(data,expected) || raw!==io.read('identity.json')) fail();
			let tx=checkpoint.receipt.authorization.restoration;
			if (!io.verify(checkpoint.before,tx.transaction_id,tx.request_id)) fail();
			let current=io.read('state.json');
			if (current!==checkpoint.before && current!==checkpoint.after) fail();
			if (current!==checkpoint.after) io.replace('state.json',current,checkpoint.after);
			if (digest(sprintf('%J',canonical(io.snapshot())))!=checkpoint.snapshot ||
				io.read('state.json')!==checkpoint.after || io.read('identity.json')!==raw) fail();
			let next={schema:1,id:original.id,fingerprint:original.fingerprint,role:'unbound',binding:null,
				joining:null,overrides:original.overrides || null,name:original.name || null,
				last_network:{controller_id:original.binding.controller_id,network_id:original.binding.network_id,
					removed:checkpoint.receipt.authorization.removed}};
			io.replace('identity.json',raw,sprintf('%J',next));
			return {role:'unbound',id:next.id};
		});
	}
	return {resume};
}
