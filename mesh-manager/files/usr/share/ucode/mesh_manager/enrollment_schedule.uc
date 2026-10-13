// SPDX-License-Identifier: GPL-2.0-only
'use strict';
export function enrollment_runner(read_identity, load_worker) {
	let worker;
	return () => {
		let identity=read_identity();
		if(identity?.enrollment?.enabled && index(['unbound','ap'],identity.role)>=0) {
			worker ??= load_worker();
			return worker();
		}
	};
}
