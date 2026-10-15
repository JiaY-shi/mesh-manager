// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal } from './model.uc';
import { validate_overrides, validate_controller_management } from './extended.uc';

const FIELDS = ['name', 'radios', 'mesh_radio', 'uplink', 'management', 'gateway', 'disable_legacy_mesh'];
export function settings_scope(data) {
	return { id: data?.id, role: data?.role, network_id: data?.role == 'ap' ? data?.binding?.network_id : data?.network_id };
}
export function validate_settings(record) {
	if (type(record) != 'object' || type(record.scope) != 'object' ||
		type(record.scope.id) != 'string' || type(record.scope.network_id) != 'string' ||
		index(['root', 'ap'], record.scope.role) < 0 || type(record.values) != 'object' ||
		length(filter(keys(record.values), key => index(FIELDS, key) < 0)))
		die('invalid_local: Invalid local settings');
	validate_overrides(record.values);
}
export function effective_settings(data, state) {
	let saved = state?.local_settings;
	if (saved) validate_settings(saved);
	return clone(saved && equal(saved.scope, settings_scope(data)) ? saved.values : data?.overrides || {});
}
export function settings_identity(data, state) {
	return data ? { ...data, overrides: effective_settings(data, state) } : data;
}
export function settings_context(data, state, local) {
	let record = { scope: settings_scope(data), values: clone(local) };
	validate_settings(record);
	if (data.role == 'root' || data.anchor!=null && data.id!=null && data.anchor.id==data.id)
		validate_controller_management(local, data.anchor!=null && data.id!=null && data.anchor.id==data.id ? data.anchor.address : data.address,null,data);
	return { record, before: effective_settings(data, state),
		identity: { id: data.id, role: data.role, network_id: data.network_id,
			binding: data.binding || null, address: data.address || null, gateway: data.gateway || null } };
}
