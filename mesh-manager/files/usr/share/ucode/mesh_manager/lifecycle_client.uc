// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal } from './model.uc';
import { local_intent, node_peers } from './extended.uc';
import { require_gateway_retained } from './authority.uc';
import { effective_settings } from './local_settings.uc';
import { require_lease } from './control_lease.uc';
import { standby_bootstrap } from './standby.uc';

// Serialize local manual operations separately. Network waits never own the
// cluster lock used by status, the agent and independent recovery.
export function lifecycle_client(io) {
	function credentials() { return map(['device.key','device.crt','network-ca.crt'], name => io.read(name)); }
	function current(frame, confirming) {
		let data = io.load('identity.json'), same = equal(data, frame.data);
		if (!same && confirming && data?.agent?.status == frame.state?.active?.status &&
			equal(data.agent.conflicts || [], frame.state.active.conflicts || [])) {
			let before = clone(frame.data), after = clone(data);
			delete before.agent.status; delete before.agent.conflicts;
			delete after.agent.status; delete after.agent.conflicts;
			same = equal(before, after);
		}
		if (!same || !equal(io.load('state.json'), frame.state) || io.boot() != frame.boot ||
			!equal(credentials(), frame.credentials) || io.now() < frame.now)
			die('preview_changed: AP identity or transaction changed while contacting the controller');
		return data;
	}
	function target(frame, request) {
		let reply = io.request(frame.data, request);
		if (reply?.controller_id != frame.data.binding.controller_id || reply.network_id != frame.data.binding.network_id)
			die('identity_error: Controller identity changed');
		return reply;
	}
	return (method, args) => io.serialized(() => {
		if (index(['mesh_preview','mesh_stage','mesh_confirm'], method) < 0)
			die('invalid_method: Invalid local Mesh operation');
		if (method != 'mesh_confirm' && type(args.enabled) != 'bool')
			die('invalid_request: Mesh target must be explicitly enabled or disabled');
		if (method == 'mesh_stage' && args.takeover !== true)
			die('takeover_required: Explicit Mesh approval is required');
		let frame = io.locked(() => {
			let data = io.load('identity.json');
			if (data?.role == 'root') return { root:true, result:io.root(method,args) };
			if (data?.role != 'ap' || !data.binding) die('not_ap: Complete Mesh enrollment first');
			if(args.enabled===false)require_gateway_retained(data,data.id);
			let state = io.load('state.json');
			if (method == 'mesh_confirm' && (!data.agent?.mesh || data.agent.transaction_id != args.transaction_id ||
				state?.active?.id != args.transaction_id || type(state.active.mesh_enabled) != 'bool'))
				die('invalid_state: Mesh confirmation does not match the AP transaction');
			return {data:clone(data),state:clone(state),boot:io.boot(),now:io.now(),credentials:credentials()};
		});
		if (frame.root) return frame.result;
		if (method == 'mesh_confirm') {
			let job = frame.data.agent;
			if (frame.state.active.status != 'committed')
				target(frame,{action:'mesh_check',request_id:job.transaction,version:job.version});
			return io.locked(() => {
				let data = current(frame, true), result = io.local.confirm(args.transaction_id);
				let changed = data.agent.status != result.status || data.cluster_version != job.version ||
					data.agent.health_confirmed !== true;
				data.agent.status = result.status; data.cluster_version = job.version;
				data.agent.health_confirmed=true;
				if (changed) io.save('identity.json', data);
				return result;
			});
		}
		let reserved = false;
		try {
			let reply = target(frame,{action:method == 'mesh_preview' ? 'mesh_intent' : 'mesh_reserve',
				request_id:args.request_id,version:args.approval?.root_version,enabled:args.enabled});
			reserved = method == 'mesh_stage';
			if (type(reply.version) != 'int' || reply.version < 1) die('protocol_error: Invalid controller Mesh version');
			if (reserved && reply.version != args.approval?.root_version) die('preview_changed: Controller intent version changed');
			let intent = args.enabled ? local_intent(reply.intent,
				{...effective_settings(frame.data,frame.state),peers:node_peers(frame.data.id,reply)},false,'bridge',frame.data.id,require_lease(reply.control),frame.data.anchor || reply.anchor) : null;
			if (method == 'mesh_preview') {
				io.locked(() => current(frame));
				let plan = io.local.mesh_preview(args.enabled,intent);
				io.locked(() => current(frame));
				if (plan.binding && (plan.binding.boot != io.boot() || io.now() >= plan.binding.expires))
					die('preview_changed: Mesh preview expired');
				return {...plan,root_version:reply.version};
			}
			return io.locked(() => {
				let data = current(frame), approval = clone(args.approval); delete approval.root_version;
				if(reply.bootstrap!=null)data.bootstrap=standby_bootstrap(reply.bootstrap);
				let staged = io.local.mesh_stage(args.enabled,intent,args.request_id,true,approval);
				data.agent = {id:'local-mesh-'+args.request_id,transaction:args.request_id,mesh:true,
					version:reply.version,transaction_id:staged.id,status:staged.status,mode:intent?.backhaul?.mode || null};
				try {
					io.save('identity.json',data);
					if (args.enabled === false) io.local.authorize_restoration?.(staged.id,args.request_id);
				}
				catch(e) { try { io.local.rollback(staged.id); } catch(ignored) {} die(e.message); }
				return staged;
			});
		} catch(e) {
			let message = e.message;
			if (reserved) try {
				let cancel = io.locked(() => {
					let data = io.load('identity.json'), active = io.load('state.json')?.active;
					return !(data?.agent?.mesh && data.agent.transaction == args.request_id && data.agent.transaction_id == active?.id &&
						index(['staged','apply_requested','applying','awaiting_confirm','committed'],active.status) >= 0);
				});
				if (cancel) {
					if (index(message || '', 'busy:') == 0) message = 'preview_changed: Mesh reservation was cancelled; review a new preview';
					target(frame,{action:'mesh_abort',request_id:args.request_id});
				}
			} catch(ignored) {}
			die(message);
		}
	});
}
