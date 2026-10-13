// SPDX-License-Identifier: GPL-2.0-only
'use strict';

export function request(connection, object, method, args) {
	if (!connection) die('reload_error: Local ubus connection unavailable');
	connection.error();
	let result = connection.call(object, method, args || {}),
		error = connection.error();
	// Void ubus methods legitimately return null; the error status is authoritative.
	if (error != null) die('reload_error: Local service request failed: ' + object + '.' + method);
	return result;
}
