// SPDX-License-Identifier: GPL-2.0-only
'use strict';

export function acquire(lock, attempts, shared) {
	attempts = type(attempts) == 'int' ? max(1, min(attempts, 5)) : 1;
	for (let n = 0; n < attempts; n++) {
		if (lock.lock(shared === true ? 'sn' : 'xn')) return true;
		if (n + 1 < attempts) sleep(20);
	}
	return false;
}
