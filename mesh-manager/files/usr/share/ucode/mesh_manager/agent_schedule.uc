// SPDX-License-Identifier: GPL-2.0-only
'use strict';

// CommonJS workers retain one module graph per process. Once enrollment or a
// role change needs a different graph, procd must start a clean process instead
// of keeping Root orchestration resident in an ordinary AP.
export function agent_runner(read_identity, load_worker) {
	let kind, worker, active_migration;
	return () => {
		let identity = read_identity(), selected = identity?.departing != null ? 'ap' :
			identity?.role == 'root' || identity?.joining != null ? 'controller' :
			identity?.role == 'ap' && identity.binding != null ? 'ap' : null;
		if (worker && selected != kind) return false;
		if (selected == null) return;
		let migration = selected == 'ap' ? identity?.migration : null,
			pending = migration && index(['complete', 'cancelled', 'expired'], migration.phase) < 0;
		// CommonJS also retains the lazy migration graph. Retire this AP VM
		// after its durable operation ends; procd restarts only this agent.
		if (worker && active_migration != null && (!pending || migration.id != active_migration)) return false;
		if (pending) active_migration = migration.id;
		if (!worker) {
			let loaded = load_worker(selected);
			if (type(loaded) != 'function') die('internal_error: Mesh agent worker is unavailable');
			kind = selected; worker = loaded;
		}
		worker();
	};
}
