// SPDX-License-Identifier: GPL-2.0-only
'use strict';

// CommonJS workers retain one module graph per process. Once enrollment or a
// role change needs a different graph, procd must start a clean process instead
// of keeping Root orchestration resident in an ordinary AP.
export function agent_runner(read_identity, load_worker) {
	let kind, worker;
	return () => {
		let identity = read_identity(), selected = identity?.departing != null ? 'ap' :
			identity?.role == 'root' || identity?.joining != null ? 'controller' :
			identity?.role == 'ap' && identity.binding != null ? 'ap' : null;
		if (worker && selected != kind) return false;
		if (selected == null) return;
		if (!worker) {
			let loaded = load_worker(selected);
			if (type(loaded) != 'function') die('internal_error: Mesh agent worker is unavailable');
			kind = selected; worker = loaded;
		}
		worker();
	};
}
