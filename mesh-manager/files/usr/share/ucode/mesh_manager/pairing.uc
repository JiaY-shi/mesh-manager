// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { allocate_lease, adopt_leases } from './control_lease.uc';
import { settings_identity } from './local_settings.uc';
import * as crypto from 'mesh_crypto';
import { clone, valid_text } from './model.uc';
import { identity_service, public_identity } from './identity.uc';
import { public_repair } from './repair.uc';
import { lifecycle_busy, configuration_busy } from './lifecycle.uc';
import { node_metadata } from './node_metadata.uc';
import { recent_presence, member_attention } from './attention.uc';
import { restoration_pending, restored_member, fresh_restoration } from './restoration.uc';
import { joining_exchange } from './joining_exchange.uc';
import { enrollment_error } from './enrollment_progress.uc';
import { invitation } from './invitation.uc';
import { enrollment_clock_witness } from './automatic_join.uc';

export function pairing_service(io) {
	let ids = identity_service(io);
	let decide;
	function state() {
		let s = io.load('cluster.json');
		if (s == null)
			return {
				schema: 1,
				version: 0,
				intent: null,
				members: {},
				invitations: [],
				requests: {},
				active: null,
				history: []
			};
		if (
			s.schema != 1 ||
			type(s.members) != 'object' ||
			type(s.requests) != 'object' ||
			type(s.invitations) != 'array' ||
			length(keys(s.members)) > 64 ||
			length(keys(s.requests)) > 64 ||
			length(s.invitations) > 16 ||
			type(s.version) != 'int' ||
			type(s.history) != 'array' ||
			s.revocations != null && (type(s.revocations)!='array' || length(s.revocations)>64)
		)
			die('corrupt_state: Invalid cluster state');
		return s;
	}
	function root() {
		let data = ids.identity();
		if (data.role != 'root') die('not_controller: This node is not a Mesh controller');
		return data;
	}
	function valid_request(r) {
		if (
			type(r) != 'object' ||
			r.protocol != 1 ||
			!match(r.id || '', /^[0-9a-f]{32}$/) ||
			!match(r.request_id || '', /^[0-9a-f]{32}$/) ||
			!match(r.secret || '', /^[0-9a-f]{64}$/)
		)
			die('invalid_request: Invalid enrollment identity');
	}
	function invite(duration) {
		let data = root(),
			s = state();
		if (lifecycle_busy(s) || io.local?.repair_status?.()?.paused === true)
			die('mesh_disabled: Mesh enrollment is unavailable during shutdown or while disabled');
		if (type(duration) != 'int' || duration < 60 || duration > 900)
			die('invalid_window: Pairing window must be 60 to 900 seconds');
		let token = io.random(32),
			hash = crypto.sha256(token);
		s.invitations = filter(
			s.invitations,
			(v) => v.boot == io.boot() && v.deadline > io.now() && !v.used
		);
		if (length(s.invitations) >= 16) die('limit_exceeded: Too many pairing windows');
		push(s.invitations, { hash, boot: io.boot(), deadline: io.now() + duration, used: false });
		io.save('cluster.json', s);
		let ca = io.read('network-ca.crt');
		return {
			protocol: 1,
			name: data.name,
			network_id: data.network_id,
			controller_id: data.id,
			address: data.address,
			port: 37901,
			enroll_port: 37902,
			ca,
			fingerprint: crypto.fingerprint(ca),
			token,
			code: 'MM1:' + data.address + ':' + crypto.fingerprint(ca) + ':' + token,
			valid_for: duration
		};
	}
	function enroll(r, source) {
		let data = root(),
			s = state();
		if (lifecycle_busy(s) || configuration_busy(s, io) || io.local?.repair_status?.()?.paused === true)
			die('mesh_disabled: Mesh enrollment is unavailable during shutdown or while disabled');
		if (r?.protocol == 1 && r.action == 'info') {
			let ca = io.read('network-ca.crt');
			return {
				protocol: 1, name: data.name, address: data.address,
				controller_id: data.id, network_id: data.network_id,
				ca, fingerprint: crypto.fingerprint(ca),
				port: 37901, enroll_port: 37902, automatic_enrollment: s.intent != null,
				...(r.clock_nonce != null ? {clock_proof: enrollment_clock_witness(data, r.clock_nonce,
					{time,read:io.read,fingerprint:crypto.fingerprint,sign:crypto.message_sign})} : {})
			};
		}
		valid_request(r);
		if (r.action == 'auto_invite') {
			if (!s.intent || !io.local_source?.(source, data.address))
				die('enrollment_not_allowed: Join from the controller management LAN');
			if (type(r.csr) != 'string' || length(r.csr) > 4096 || r.id == data.id ||
				!crypto.sign(io.read('network-ca.key'), io.read('network-ca.crt'), r.csr, r.id))
				die('invalid_identity: Invalid device CSR');
			let previous = s.members[r.id];
			if (previous && (previous.authorized !== false || !restored_member(s, data, previous)))
				die('already_registered: Restore and revoke the existing membership before applying again');
			let ticket = invite(300); s = state();
			let v = s.invitations[length(s.invitations) - 1];
			v.local = true; v.automatic = true; v.node_id = r.id; v.csr_hash = crypto.sha256(r.csr);
			io.save('cluster.json', s); return ticket;
		}
		if (r.action == 'join') {
			if (
				r.id == data.id ||
				type(r.csr) != 'string' ||
				length(r.csr) > 4096 ||
				!match(r.token || '', /^[0-9a-f]{64}$/) ||
				r.network_id != data.network_id ||
				!valid_text(r.name, 1, 64)
			)
				die('invalid_request: Invalid joining request');
			let existing = s.requests[r.request_id],
				secret_hash = crypto.sha256(r.secret),
				token_hash = crypto.sha256(r.token);
			if (existing) {
				if (
					existing.id != r.id ||
					!crypto.constant_equal(existing.secret_hash, secret_hash) ||
					existing.csr != r.csr ||
					!crypto.constant_equal(existing.token_hash, token_hash)
				)
					die('request_reused: Enrollment request was reused');
				let still_approved=existing.status=='approved' && s.members[r.id]?.authorized===true &&
					s.members[r.id].certificate==crypto.fingerprint(existing.cert);
				return { request_id: r.request_id, status: existing.status=='approved' && !still_approved ? 'revoked' : existing.status,
					...(still_approved ? { cert: existing.cert,
						controller_id: data.id, network_id: data.network_id } : {}) };
			}
			let v = filter(
				s.invitations,
				(v) =>
					!v.used &&
					v.boot == io.boot() &&
					v.deadline > io.now() &&
					crypto.constant_equal(v.hash, token_hash)
			)[0];
			if (!v) die('invitation_expired: Invitation is expired or already consumed');
			if (v.local && (v.node_id != r.id || v.csr_hash != crypto.sha256(r.csr) ||
				!io.local_source?.(source, data.address)))
				die('enrollment_not_allowed: Automatic enrollment identity or LAN source changed');
			if (!v.local && (v.wired || v.automatic))
				die('invitation_expired: Start a new automatic enrollment request');
			let previous=s.members[r.id];
			if (previous && (previous.authorized !== false || !restored_member(s,data,previous)))
				die('already_registered: Restore and revoke the existing membership before applying again');
			if (
				length(filter(values(s.requests), (q) => q.id == r.id && q.status == 'pending')) ||
				length(keys(s.requests)) >= 64
			)
				die('already_registered: Node already registered or enrollment capacity reached');
			// Signing verifies CSR proof of possession, public-key-derived ID and exact subject.
			let cert = crypto.sign(io.read('network-ca.key'), io.read('network-ca.crt'), r.csr, r.id);
			if (!cert) die('invalid_identity: Invalid CSR proof of possession');
			v.used = true;
			s.requests[r.request_id] = {
				id: r.id,
				name: r.name,
				csr: r.csr,
				cert,
				secret_hash,
				token_hash,
				...(previous ? { previous_membership: crypto.sha256(sprintf('%J', previous)) } : {}),
				status: 'pending',
				created: time()
			};
			io.save('cluster.json', s);
			if (v.automatic) decide(r.request_id, true);
			return { request_id: r.request_id, status: 'pending' };
		}
		if (r.action == 'join_status') {
			let q = s.requests[r.request_id];
			if (!q || q.id != r.id || !crypto.constant_equal(q.secret_hash, crypto.sha256(r.secret)))
				die('not_authorized: Enrollment query is not authorized');
			let still_approved=q.status=='approved' && s.members[q.id]?.authorized===true &&
				s.members[q.id].certificate==crypto.fingerprint(q.cert);
			return {
				request_id: r.request_id,
				status: q.status=='approved' && !still_approved ? 'revoked' : q.status,
				cert: still_approved ? q.cert : null,
				controller_id: data.id,
				network_id: data.network_id
			};
		}
		die('invalid_method: Enrollment does not accept configuration requests');
	}
	decide = function(request_id, approve) {
		root();
		let s = state(),
			q = s.requests[request_id];
		if (approve === true && (lifecycle_busy(s) || configuration_busy(s, io) || io.local?.repair_status?.()?.paused === true))
			die('mesh_disabled: Mesh enrollment is unavailable during shutdown or while disabled');
		if (!q) die('not_found: Joining request not found');
		if (q.status != 'pending') return { status: q.status, id: q.id };
		if (approve === true) {
			let previous=s.members[q.id];
			if (previous && (previous.authorized !== false || !restored_member(s,root(),previous) ||
				q.previous_membership != crypto.sha256(sprintf('%J',previous))))
				die('membership_changed: The revoked membership changed; review a new application');
			if (!previous && length(keys(s.members)) >= 64) die('limit_exceeded: Maximum 64 nodes');
			if (previous && previous.certificate == crypto.fingerprint(q.cert))
				die('invalid_identity: Re-enrollment requires a new node certificate');
			if (previous) {
				s.revocations=s.revocations || [];
				push(s.revocations,{id:previous.id,name:previous.name,removed:previous.removed,
					restoration_confirmed:true});
				s.revocations=slice(s.revocations,-64);
			}
			let control = allocate_lease(s, q.id);
			adopt_leases(s);
			q.status = 'approved';
			s.members[q.id] = {
				id: q.id,
				control,
				name: q.name,
				authorized: true,
				version: 0,
				seen: null,
				status: null,
				report: null,
				certificate: crypto.fingerprint(q.cert)
			};
		} else q.status = 'rejected';
		io.save('cluster.json', s);
		return { id: q.id, status: q.status };
	};
	function join(value, name, overrides, takeover) {
		if (takeover !== true) die('takeover_required: Joining needs local takeover consent');
		let data = ids.identity();
		if (data.role != 'unbound' || data.binding || data.joining)
			die('already_bound: Leave the current network or complete the current request first');
		let v = invitation(value);
		if (v.controller_id == data.id) die('invalid_identity: A controller cannot join itself');
		if (!valid_text(name, 1, 64)) die('invalid_name: Invalid node name');
		io.validate_overrides?.(overrides);
		data.name = name;
		data.overrides = clone(overrides);
		data.joining = {
			invitation: v,
			request_id: io.random(16),
			secret: io.random(32),
			status: 'requesting'
		};
		io.write('join-ca.crt', v.ca);
		io.save('identity.json', data);
		return { request_id: data.joining.request_id, status: 'requesting' };
	}
	function join_tick(absolute_deadline) {
		return joining_exchange(io, invitation).tick(absolute_deadline);
	}
	function revoke(id) {
		let controller=root();
		let s = state(),
			member = s.members[id];
		if (!member) die('not_found: Node not found');
		if (member.authorized === false) return { id, authorized: false };
		if (member.authorized !== true) die('not_authorized: AP authorization state is unknown');
		if (lifecycle_busy(s) || configuration_busy(s,io) || restoration_pending(s,member))
			die('busy: Complete configuration and recovery operations before revoking the AP');
		if (member.mesh_paused !== true)
			die('ap_restore_required: Disable and restore the AP before revoking its identity');
		if (!restored_member(s,controller,member))
			die('ap_restore_unverified: The AP has no matching confirmed restoration receipt');
		if (!fresh_restoration(io,controller,member))
			die('node_offline: A fresh complete restoration report is required before revocation');
		member.authorized = false;
		member.removed = time();
		// Old approved requests must not return their former certificate again.
		for (let q in values(s.requests))
			if (q.id==id && q.status=='approved') q.status='revoked';
		io.save('cluster.json', s);
		return { id, authorized: false };
	}
	let metadata=node_metadata(io);
	function status(view) {
		let full = !view || view == 'full';
		let identity = io.load('identity.json'),
			s = state();
		let result = {
			identity: public_identity(settings_identity(identity, io.load('state.json')),io.public_enrollment?.(identity)),
			version: identity?.role == 'ap' ? identity.cluster_version || 0 : s.version,
			members: map(values(s.members), (m) => {
				let seen = io.presence?.(m.id) || m;
				let member = {
					id: m.id,
					name: m.name,
					authorized: m.authorized,
					...(m.authorized===false ? {removed:m.removed || null} : {}),
					version: m.version,
					status: m.status,
					online: recent_presence(seen, io.boot(), io.presence_now?.() ?? io.now()),
					mesh_paused: m.mesh_paused === true,
					error: m.error || null
				};
				if (full || view == 'nodes')
					member.restoration_confirmed=restored_member(s,identity,m);
				if (index(['overview','diagnostics'],view)>=0)
					member.attention=member_attention(m,member.online,s.intent?.backhaul?.mode);
				if (full) member.report = m.report;
				else if (m.report && view == 'diagnostics') member.report = { software: m.report.software || null };
				else if (m.report && view == 'nodes')
					member.report = { model: m.report.model, configured: m.report.configured,
						local_version: m.report.local_version, mesh_enabled: m.report.mesh_enabled,
						drift: m.report.drift, backhaul: m.report.backhaul,
						...(m.report.configured === false ? {configuration: {
							status: index(['staged','apply_requested','awaiting_confirm','rolled_back','expired','rollback_conflict','error'],
								m.report.command?.status) >= 0 ? m.report.command.status : null,
							error: enrollment_error(m.report.command?.error)
						}} : {}),
						transaction:m.report.transaction ? {id:m.report.transaction.id,
							kind:m.report.transaction.kind,status:m.report.transaction.status,
							mesh_enabled:m.report.transaction.mesh_enabled,
							...(m.report.transaction.restore_recheck === true ? {restore_recheck:true} : {})} : null};
				else if (m.report && view == 'backhaul') member.report = { backhaul: m.report.backhaul };
				else if (m.report && view == 'overview')
					member.report = { backhaul: m.report.backhaul ? { active: m.report.backhaul.active } : null,
						management: m.report.management ? { up: m.report.management.up === true,
							addresses: m.report.management.addresses || [] } : null };
				if (full || index(['nodes', 'wireless', 'backhaul'], view) >= 0) {
					member.repair = public_repair(m.repair);
					if (!full && member.repair) {
						member.repair.has_plan = member.repair.plan != null;
						delete member.repair.plan;
					}
				}
				return member;
			}),
			active: io.public_active?.(s.active, !full ? false : null) || null
		};
		if (full || index(['wireless', 'backhaul'], view) >= 0)
			result.intent = s.intent ? io.public_intent(s.intent) : null;
		if (full || view == 'nodes') {
			result.requests = map(keys(s.requests), (id) => ({
				request_id: id,
				id: s.requests[id].id,
				name: s.requests[id].name,
				status: s.requests[id].status
			}));
		}
		if (full || view == 'history') {
			result.history = s.history;
			result.repair_history = s.repair_history || [];
		}
		if (full || view=='nodes' || view=='history')
			result.revocations=map(s.revocations || [],r=>({id:r.id,name:r.name,removed:r.removed,
				restoration_confirmed:r.restoration_confirmed===true}));
		if (!full && result.active && index(['complete', 'partial', 'failed', 'rolled_back', 'expired'],
			result.active.phase) >= 0 && index(['wireless', 'backhaul'], view) < 0) result.active = null;
		return result;
	}
	return { state, invite, enroll, decide, join, join_tick, revoke,
		rename_preview:metadata.preview,rename:metadata.apply,status,root };
}
