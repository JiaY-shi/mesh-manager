// SPDX-License-Identifier: GPL-2.0-only
// Pure policy predicates: idle scheduling must not load crypto or transaction modules.
'use strict';
export function private_address(value) {
	if (type(value) != 'string' || match(value, /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/)?.[0] !== value) return false;
	let p = map(split(value, '.'), (item) => int(item));
	return (
		!length(filter(p, (n) => n < 0 || n > 255)) &&
		(p[0] == 10 ||
			(p[0] == 172 && p[1] >= 16 && p[1] <= 31) ||
			(p[0] == 192 && p[1] == 168) ||
			(p[0] == 169 && p[1] == 254))
	);
}
export function valid_anchor(value) {
	return type(value) == 'object' && length(keys(value)) == 5 &&
		type(value.id)=='string' && length(value.id)==32 && match(value.id, /^[0-9a-f]{32}$/) && private_address(value.address) &&
		value.control_address == '169.254.254.1' && index(['router','bridge'], value.gateway) >= 0 &&
		type(value.certificate)=='string' && length(value.certificate)==64 && match(value.certificate, /^[0-9a-f]{64}$/) != null;
}
export function migration_pending(m) { return m!=null && index(['complete','cancelled','expired'],m.phase)<0; }
