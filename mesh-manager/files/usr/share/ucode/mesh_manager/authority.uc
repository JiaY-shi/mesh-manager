// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { valid_anchor as anchor_valid } from './authority_model.uc';
import { clone } from './model.uc';

export function valid_anchor(value) { return anchor_valid(value); }
export function require_anchor(value) {
	if (!valid_anchor(value)) die('migration_conflict: Invalid data gateway anchor');
	return clone(value);
}
export function physical_root(identity, intent) {
	return intent?.controller === true && (identity?.anchor == null ? identity?.role == 'root' :
		valid_anchor(identity.anchor) && identity.anchor.id == identity.id);
}
export function data_binding(identity) {
	if (identity?.anchor != null) {
		let a = require_anchor(identity.anchor);
		return { controller_id:a.id, address:a.address, control_address:a.control_address,
			controller_certificate:a.certificate, network_id:identity.network_id || identity.binding?.network_id,
			...(substr(identity.gateway_key || '',0,32)==a.id ? {controller_key:identity.gateway_key} : {}),
			ca_fingerprint:identity.ca_fingerprint || identity.binding?.ca_fingerprint };
	}
	return identity?.binding || null;
}

export function authority_busy(identity, cluster) {
	let m = identity?.migration || cluster?.migration;
	return identity?.authority_fence != null || m != null &&
		index(['complete','cancelled','expired'], m.phase) < 0;
}

// A public request cannot authorize a private role transition. Configuration
// recovery continues through its existing journal and independent watchdog.
export function require_authority(identity, cluster) {
	if(identity?.certificate_update!=null)
		die('certificate_pending: Local certificate replacement is recovering');
	if (authority_busy(identity, cluster))
		die('migration_pending: Finish or cancel the controller migration before changing configuration');
}
export function require_gateway_retained(identity, id) {
	if(valid_anchor(identity?.anchor) && identity.anchor.id==id &&
		(identity.role!='root' || identity.id!=id))
		die('gateway_retained: Migrate the controller back to the data gateway before disabling or removing it');
}
