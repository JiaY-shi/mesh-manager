// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal } from './model.uc';
import { handoff_state, handoff_capture, handoff_check, handoff_request,
	handoff_completion, handoff_finish } from './first_handoff.uc';

const COLD = 210000, CLEANUP = 12000, WRITE = 5000, MARGIN = 1000;
const CAPTURE = ['scope', 'journal', 'snapshot', 'boot', 'now', 'transport'];
const MATERIAL = ['identity', 'key', 'join_ca', 'network_ca', 'cert'];
function integer(v) { return type(v) == 'int' && v >= 0 && v <= 1000000000000000; }
function exact(v, fields) { return type(v) == 'object' && equal(sort(keys(v)), sort(fields)); }
function conflict() { die('handoff_conflict: Original first configuration scope changed'); }
function timeout() { die('handoff_timeout: Original first configuration deadline expired'); }
function state(c) { return handoff_state(c.scope, c.journal, c.snapshot, c.boot, c.now); }
function present(c, outer) {
	// D validates the genuine ten-field native owner or proven absence. It does
	// not establish that an IO callback actually inspected that native owner.
	return handoff_capture(c.scope, c.journal, c.snapshot, c.boot, c.now, c.transport, outer);
}
function unchanged(before, after, started, deadline) {
	return equal(before.scope, after.scope) && before.journal === after.journal &&
		before.snapshot === after.snapshot && before.boot === after.boot &&
		after.now >= started && after.now < deadline;
}

// Private finite orchestration. The adapter owns actual native/mTLS observation,
// original-provenance restore, cleanup/reap and full-scope durable CAS; public
// request JSON must never be used to supply these callbacks or observations.
export function handoff_client(io) {
	function capture() {
		let c = io.capture();
		if (!exact(c, CAPTURE) || !exact(c.scope, MATERIAL) || !integer(c.now) ||
			type(c.boot) != 'string' || !length(c.boot) || length(c.boot) > 64 ||
			type(c.snapshot) != 'string' || c.journal != null && type(c.journal) != 'string')
			conflict();
		return clone(c);
	}
	function pending(s, restored) {
		return { stage: s.stage, retain: true, joined: false, restored: restored === true, error: s.error };
	}
	function step(outer) {
		// The caller supplies its existing absolute operation deadline. This step
		// never constructs another cold-operation deadline after an IO callback.
		if (!integer(outer)) timeout();
		let original = io.locked(capture), s = state(original);
		if (s.stage == 'blocked') return pending(s, false);
		if (outer <= original.now) timeout();
		present(original, outer);
		if (s.stage == 'configuring') {
			if (s.restore !== true) conflict();
			if (original.transport != null) return pending(s, false);
			let deadline = min(outer, original.now + COLD),
				cold = { ...clone(original), started: original.now, deadline },
				result = io.restore_original(clone(cold), deadline);
			return io.locked(() => {
				let fresh = capture();
				if (fresh.now >= deadline) timeout();
				if (!unchanged(original, fresh, original.now, deadline) ||
					!exact(result, ['restored', 'transport']) || result.restored !== true ||
					result.transport == null || !equal(fresh.transport, result.transport)) conflict();
				present(fresh, deadline);
				let next = state(fresh);
				if (next.stage != 'configuring' || next.restore !== true) conflict();
				return pending(next, true);
			});
		}
		if (s.stage != 'committed') return pending(s, false);

		let frame = present(original, outer),
			health_deadline = frame.deadline - CLEANUP - WRITE - MARGIN;
		if (health_deadline <= original.now) timeout();
		let request = handoff_request(frame, io.nonce()),
			proof = clone(io.health(clone(frame), clone(request), health_deadline)),
			plan, cleanup_deadline;
		io.locked(() => {
			let fresh = capture();
			if (fresh.now >= health_deadline) timeout();
			if (!equal(proof?.request, request) || !handoff_check(frame, fresh.scope,
				fresh.journal, fresh.snapshot, fresh.boot, fresh.now, fresh.transport)) conflict();
			plan = handoff_completion(frame, fresh.scope, fresh.journal, fresh.snapshot,
				fresh.boot, fresh.now, fresh.transport, proof, io.wall());
			cleanup_deadline = min(fresh.now + CLEANUP, frame.deadline - WRITE - MARGIN);
			if (cleanup_deadline <= fresh.now) timeout();
		});
		let receipt = clone(io.cleanup(clone(plan.cleanup), cleanup_deadline));
		return io.locked(() => {
			let fresh = capture();
			if (fresh.now >= cleanup_deadline) timeout();
			let identity = handoff_finish(plan, fresh.scope, fresh.journal, fresh.snapshot,
				fresh.boot, fresh.now, fresh.transport, receipt, io.wall()),
				write_deadline = min(fresh.now + WRITE, frame.deadline);
			// One actual full-scope CAS write. Failed/late writes are never undone:
			// the caller can inspect the retained marker or known successor later.
			io.commit(clone(fresh), identity, write_deadline);
			let after = capture(), expected = { ...clone(fresh.scope), identity };
			if (after.now >= write_deadline || after.now >= frame.deadline) timeout();
			if (!equal(after.scope, expected) || fresh.journal !== after.journal ||
				fresh.snapshot !== after.snapshot || fresh.boot !== after.boot ||
				after.now < fresh.now || after.transport != null) conflict();
			return { stage: 'joined', retain: false, joined: true, restored: false, error: null };
		});
	}
	return { step };
}
