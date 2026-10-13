// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { valid_text } from './model.uc';

// Informational metadata only. Never use version labels to authorize a peer
// or substitute for the actual protocol and hardware capability checks.
export function software_status(value) {
	let result = {};
	for (let field in ['distribution','version','revision','target','kernel'])
		result[field] = valid_text(value?.[field], 1, 64, true) ? value[field] : null;
	return result;
}
