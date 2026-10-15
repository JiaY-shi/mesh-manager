// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { control_ingress, ingress_response } from './control_ingress.uc';
import { effective_settings, settings_context } from './local_settings.uc';
import * as fs from 'fs';
import { run } from 'mesh_process';
import * as durable from './durable.uc';
import * as client_events from './client_events.uc';
import { identity_service } from './identity.uc';
import * as crypto from 'mesh_crypto';
import { pairing_service } from './pairing.uc';
import { invitation, joining_code } from './invitation.uc';
import { handoff_prepare } from './first_handoff.uc';
import { handoff_tick } from './handoff_runtime.uc';
import { cluster_service, public_active } from './cluster.uc';
import { validate_overrides, validate_controller_management, controller_intent } from './extended.uc';
import { canonical, clone, equal, public_intent } from './model.uc';
import { dispatch as local_dispatch, snapshot, guest_network_snapshot, status_view, observe_clients, publish_observation,
	root_bootstrap_wifi } from './runtime.uc';
import { discover, discover_wireless } from './discovery.uc';
import { onboard_start, onboard_status, onboard_stop, onboarding_device,
	onboard_capture, onboarding_transport, onboarding_authorize, onboard_stop_owned,
	onboard_resume_start, onboarding_resume_continues, onboard_cleanup_capture } from './onboarding.uc';
import { enrollment_resume_service } from './enrollment_resume.uc';
import { approval_valid } from './joining_exchange.uc';
import { public_lifecycle, lifecycle_busy, configuration_busy } from './lifecycle.uc';
import { automatic_controller, automatic_ticket, synchronize_enrollment_clock } from './automatic_join.uc';
import { physical_port, lan_source } from './wired.uc';
import { enrollment_service, cancel_enrollment } from './enrollment.uc';
import { enrollment_runtime, enrollment_observation, enrollment_uptime } from './enrollment_runtime.uc';
import { public_repair } from './repair.uc';
import { root_settings } from './local_settings_service.uc';
import { repair_client, serialized_repair } from './repair_client.uc';
import { lifecycle_client } from './lifecycle_client.uc';
import { exchange as transport_exchange, probe, probe_managed } from './peer_transport.uc';
import { seal, validate_request } from './signed_response.uc';
import { restoration_epoch } from './restoration.uc';
import {require_authority} from './authority.uc';
import {public_migration} from './migration_model.uc';
import {anchor_roster} from './anchor_roster.uc';
import {certificate_renewal} from './certificate_renewal.uc';
const certificates=certificate_renewal(durable);

import { agent_local } from './agent_local.uc';
import { sanitize_report } from './agent_report.uc';
import { ap_agent_tick, agent_exchange } from './ap_agent.uc';

const REPORTS = '/var/run/mesh-manager-reports';

function report_epoch(report) {
	return { version: report?.version || 0, local_version: report?.local_version || 0,
		transaction: report?.transaction?.id || null, status: report?.transaction?.status || null,
		mesh_enabled: report?.mesh_enabled ?? null };
}
function sampled_health(health) {
	if (type(health) != 'object' || type(health.ok) != 'bool') return null;
	let raw = type(health.checks) == 'array' ? health.checks : [];
	let checks = filter(raw, (c) => type(c?.name) == 'string' &&
		length(c.name) <= 64 && type(c.ok) == 'bool');
	return { ok: health.ok, data_path_verified: health.data_path_verified === true,
		checks: map(slice(checks, 0, 64), (c) => ({ name: c.name, ok: c.ok })),
		truncated: length(checks) != length(raw) || length(checks) > 64 ||
			(health.checks != null && type(health.checks) != 'array') };
}
function sampled_quality(quality) {
	if (type(quality) != 'object' || type(quality.signal_dbm) != 'int' ||
		quality.signal_dbm < -127 || quality.signal_dbm > 0 ||
		index(['int', 'double'], type(quality.phy_rate_mbps)) < 0 ||
		quality.phy_rate_mbps <= 0 || quality.phy_rate_mbps > 1000000) return null;
	return { signal_dbm: quality.signal_dbm, phy_rate_mbps: quality.phy_rate_mbps,
		channel: type(quality.channel) == 'int' ? quality.channel : null };
}
export function topology_report_digest(report) {
	let path=type(report?.backhaul)=='object' ? report.backhaul : null;
	return crypto.sha256(sprintf('%J',canonical({management:report?.management ?? null,
		backhaul:path ? {active:path.active ?? null,wired:path.wired ?? null,wireless:path.wireless ?? null} : null,
		model:report?.model ?? null,mesh_enabled:report?.mesh_enabled ?? null,
		version:report?.version ?? null,local_version:report?.local_version ?? null,drift:report?.drift ?? null})));
}
function observe_report(id, report, binding) {
	if (!match(id || '', /^[0-9a-f]{32}$/)) return;
	let dir = fs.lstat(REPORTS);
	if (!dir) {
		if (!fs.mkdir(REPORTS, 0700)) return;
	} else if (dir.type != 'directory' || dir.uid != 0 || dir.mode & 0077) return;
	let path = REPORTS + '/' + id;
	if (type(report.version) != 'int' || report.version < 0 || type(report.local_version) != 'int' || report.local_version < 0) {
		fs.unlink(path);return;
	}
	let payload = sprintf('%J', { boot: durable.boot(), seen:durable.now(), binding, epoch: report_epoch(report),
		restoration:restoration_epoch(report),
		topology_digest:topology_report_digest(report),
		health: sampled_health(report.health), quality: sampled_quality(report.backhaul?.quality) });
	if (length(payload) > 8192) { fs.unlink(path); return; }
	let file = fs.open(path, 'w', 0600);
	if (!file) return;
	file.write(payload); file.close();
}

function observed_report(id, binding, persisted) {
	if (!match(id || '', /^[0-9a-f]{32}$/)) return null;
	let path = REPORTS + '/' + id, st = fs.lstat(path);
	if (!st || st.type != 'file' || st.uid != 0 || st.mode & 0077 || st.size > 8192) return null;
	try {
		let report = json(fs.readfile(path) || 'null');
		return report?.boot == durable.boot() && equal(report.binding, binding) &&
			equal(report.epoch, report_epoch(persisted)) ? report : null;
	} catch (e) { return null; }
}
export function observed_topology_report(id, binding, persisted) {
	let report=observed_report(id,binding,persisted);
	if(!report || report.topology_digest!=topology_report_digest(persisted))return null;
	return {boot:report.boot,seen:report.seen ?? null,quality:report.quality || null};
}
export function restoration_observation(id, persisted, binding) {
	let report=observed_report(id,binding,persisted);
	if (!report || report.topology_digest != topology_report_digest(persisted) ||
		!equal(report.restoration,restoration_epoch(persisted))) return null;
	return {boot:report.boot,seen:report.seen ?? null,confirmed:report.restoration.confirmed};
}

function exchange(binding, request, enrollment, device) {
	return transport_exchange(binding,request,enrollment,
		enrollment ? onboarding_device(binding.address) : device);
}
function onboarding_scope_material() {
	let captured = onboard_capture(), scope = { ...captured.scope,
		state: durable.read('state.json'), cluster: durable.read('cluster.json') }, data;
	try { data = json(scope.identity); }
	catch (e) { die('identity_error: Original onboarding identity is unavailable'); }
	if (data?.enrollment?.enabled === true && data.enrollment.phase == 'wireless' ||
		data?.joining?.approval?.handoff != null || data?.handoff != null)
		scope.snapshot = sprintf('%J', snapshot());
	return scope;
}
export function probe_control(binding, device) {
	if (index(['mm-cw', 'mm-cm'], device) < 0)
		die('invalid_device: Probe must use a managed control interface');
	return probe(binding, device);
}
export function probe_management(binding) {
	return probe(binding, null);
}
export function presence(id) {
	if (!match(id || '', /^[0-9a-f]{32}$/)) return null;
	try {
		return json(fs.readfile('/var/run/mesh-manager-seen-' + id) || 'null');
	} catch (e) {
		return null;
	}
}
function seen(id) {
	publish_observation(
		'/var/run/mesh-manager-seen-' + id,
		{ boot: durable.boot(), seen: durable.now() }
	);
}
function io() {
	let local = agent_local();
	return {
		...durable,
		local,
		network_snapshot: guest_network_snapshot,
		exchange,
		join_transport: onboarding_transport,
		join_capture: onboarding_scope_material,
		join_snapshot: () => sprintf('%J', snapshot()),
		join_handoff: handoff_prepare,
		join_authorize: (handle, scope, checkpoint, expected, timeout) =>
			onboarding_authorize(handle, scope, checkpoint, expected, timeout, onboarding_scope_material),
		join_exchange: (binding, request, transport, timeout_ms) => {
			if (!equal(transport, onboarding_transport(binding.address)))
				die('identity_error: Original joining transport changed');
			return transport_exchange(binding, request, true, transport?.device || null, timeout_ms);
		},
		validate_overrides,
		public_intent,
		public_active,
		presence,
		seen,
		observe_clients: client_events.observe,
		observe_report,
		observed_report,
		bootstrap_wifi:root_bootstrap_wifi,
		restoration_observation,
		sanitize_report,
		local_source: (source) => lan_source(source, snapshot().network.lan?.values.device)
	};
}
function migration(i) { return require('mesh_manager.migration_worker')(i || io()); }
function services() {
	let i = io(),
		pair = pairing_service(i);
	return { io: i, pair, cluster: cluster_service(i, pair) };
}
let enrollment_worker_runtime;
function enrollment_io(runtime) {
	runtime=runtime || enrollment_runtime(durable);
	let resume = enrollment_resume_service({ progress: runtime.progress, now: enrollment_uptime,
		scope: onboarding_scope_material, decode: joining_code,
		verify: { ca: (pem, fp) => crypto.fingerprint(pem) == fp,
			leaf: crypto.verify_leaf, approval: approval_valid, key: crypto.key_fingerprint },
		resume_poll: (frame, deadline) => {
			if (!runtime.progress.check(frame) || enrollment_uptime() >= deadline) return false;
			pairing_service(io()).join_tick(deadline / 1000);
			return true;
		},
		resume_start: (capture, deadline) => onboard_resume_start(capture, deadline, onboarding_scope_material), cleanup_owned: onboard_stop_owned,
		resume_continues: onboarding_resume_continues });
	function inspect(candidate, frame) {
		let nonce=durable.random(16), started=enrollment_uptime(),
			argv=['/usr/libexec/mesh-manager-channel','inspect-clock',candidate.address,'37902',nonce],device=onboarding_device(candidate.address);
		if(device)push(argv,device);
		let result=run(argv,'',9000),reply;
		if(result?.code!=0)die('peer_unavailable: Controller identity lookup failed');
		try{reply=json(result.stdout);}catch(e){die('protocol_error: Invalid controller identity');}
		let info=reply?.ok===true ? reply.data : null;
		automatic_controller(info,candidate.address,candidate.fingerprint,crypto.fingerprint);
		if(candidate.controller_id && info.controller_id!=candidate.controller_id)
			die('identity_error: Controller discovery identity changed');
		durable.locked(()=>{
			if(!runtime.check_locked(frame) || durable.load('identity.json')?.role!='unbound' ||
				durable.load('identity.json')?.joining)die('preview_changed: Enrollment changed before clock synchronization');
			synchronize_enrollment_clock(info,nonce,enrollment_uptime()-started,{
				time,verify_at:crypto.message_verify_at,
				ca_status:(ca,wall)=>crypto.certificate_status(ca,null,null,wall).ca.status,
				adjust:wall=>run(['/bin/date','-u','-s','@'+wall],'',2000)?.code==0
			});
		});
		return info;
	}
	function ticket(info, current) {
		return automatic_ticket(info,current,{random:durable.random,
			csr:id=>crypto.csr(durable.read('device.key'),id),request:(binding,request)=>{
				// Anonymous inspection never receives a token or private key. The
				// unlinked CA descriptor pins the following TLS request without
				// changing the actor's original durable material or leaving files.
				let file=fs.mkstemp('/var/run/mesh-manager-ca.XXXXXX'),result;
				if(!file)die('storage_error: Temporary controller trust unavailable');
				try {
					if(file.write(binding.ca)!=length(binding.ca) || !file.flush())die('storage_error: Temporary controller trust unavailable');
					let path='/proc/'+fs.readlink('/proc/self')+'/fd/'+file.fileno();
					let argv=['/usr/libexec/mesh-manager-channel','client',binding.address,'37902',path,'-','-',binding.controller_id];
					let device=onboarding_device(binding.address);if(device)push(argv,device);
					result=run(argv,sprintf('%J',request),16000);
				} catch(error) {file.close();die(error.message);}
				file.close();
				if(result?.code!=0)die('peer_unavailable: Authenticated controller connection failed');
				let reply;try{reply=json(result.stdout);}catch(error){die('protocol_error: Invalid controller response');}
				if(reply?.ok!==true)die((reply?.error?.code || 'peer_error')+': Controller rejected automatic enrollment');
				return reply.data;
			}});
	}

	function submit(frame,invite,e,port) {
		return durable.locked(()=>{
			if(!runtime.check_locked(frame))return false;
			let overrides=clone(e.local);if(port)overrides.uplink=port;
			pairing_service(io()).join(invitation(invite),e.name,overrides,true);return true;
		});
	}
	return {
		identity:()=>identity_service(io()).identity(),load_identity:()=>durable.load('identity.json'),
		save_identity:data=>durable.save('identity.json',data),validate_overrides,random:durable.random,
		boot:durable.boot,now:()=>enrollment_uptime()/1000,progress:runtime.progress,boundary:runtime.boundary,
		managed:()=>local_dispatch('status',{view:'nodes'}).mesh_enabled===true,
		resume_tick: resume.tick,
		wired:()=>discover(durable.load('identity.json')),
		wireless:()=>discover_wireless(durable.load('identity.json'),null,null,null,10),
		cleanup:onboard_stop,
		cancel_attempt:expected=>{
			let handle, cleanup_error;
			let changed=durable.locked(()=>{
				let data=durable.load('identity.json');
				if(!equal(data,expected) || !data?.enrollment?.enabled || data.role!='unbound' || data.joining?.status!='rejected')return false;
				try { handle=onboard_cleanup_capture(); } catch(e) { cleanup_error=e; }
				let error=data.joining.error || 'not_authorized';data.joining=null;
				data.enrollment={...data.enrollment,epoch:durable.random(16),status:'waiting_retry',
					code:null,error,retry:{boot:durable.boot(),next:enrollment_uptime()+30000}};
				durable.save('identity.json',data);return true;
			});
			if(!changed)return false;
			if(cleanup_error)die(cleanup_error.message);
			if(handle && !onboard_stop_owned(handle))die('cleanup_conflict: Original rejected-request transport was preserved');
			return true;
		},
		join_wired:(frame,candidate,e)=>{
			if(!runtime.progress.check(frame))return false;
			let info=inspect(candidate,frame);if(!runtime.progress.check(frame))return false;
			let port=physical_port(candidate.address);if(!port || !runtime.progress.check(frame))return false;
			if(e.code)return submit(frame,{...info,token:joining_code(e.code).token},e,port);
			let credential=ticket(info,frame.identity);
			return submit(frame,credential,e,port);
		},
		join_wireless:(frame,point,e)=>{
			let captured=durable.locked(()=>{
				if(!runtime.check_locked(frame))return false;
				return onboard_capture();
			});
			if(!captured || !runtime.progress.check(frame))return false;
			// Scan, association, DHCP and owned cleanup cannot hold the durable
			// lock. Native launch still checks the exact captured bytes and boot.
			if(!e.code) {
				onboard_stop();if(!runtime.progress.check(frame))return false;
				let connected=onboard_start({...point,password:e.password,takeover:true},captured),credential;
				try {
					if(!runtime.progress.check(frame)){onboard_stop_owned({generation:connected.generation});return false;}
					credential=ticket(inspect({address:connected.controller},frame),frame.identity);
				} catch(error) {onboard_stop_owned({generation:connected.generation});die(error.message);}
				if(!onboard_stop_owned({generation:connected.generation}))die('cleanup_conflict: Discovery transport could not be restored');
				if(!runtime.progress.check(frame))return false;
				return runtime.boundary(frame.identity,d=>{d.enrollment={...d.enrollment,code:credential.code,
					bssid:point.bssid,device:point.device,phase:'wireless',status:'searching_wireless'};});
			}
			if(!onboard_status().connected) {
				onboard_stop();
				if(!runtime.progress.check(frame))return false;
				onboard_start({...point,code:e.code,password:e.password,takeover:true},captured);
			}
			if(!runtime.progress.check(frame))return false;
			let code=joining_code(e.code),info=inspect(code,frame);
			return submit(frame,{...info,token:code.token},e,null);
		}
	};
}
export function enrollment_tick() {
	enrollment_worker_runtime ??= enrollment_runtime(durable);
	return enrollment_worker_runtime.run(()=>{
		if (!handoff_tick(enrollment_worker_runtime.progress, onboarding_scope_material))
			enrollment_service(enrollment_io(enrollment_worker_runtime)).tick();
	});
}
function repair_target(data, action, request_id, version, purpose) {
	if (data?.role != 'ap' || !data.binding) die('not_ap: Only an enrolled AP can restore controller configuration');
	let target = agent_exchange(data.binding, { protocol: 1, network_id: data.binding.network_id,
		action, request_id, version, purpose }, data);
	if (target.controller_id != data.binding.controller_id || target.network_id != data.binding.network_id)
		die('identity_error: Controller identity changed');
	return target;
}
function status_frame(i, detail) {
	return i.locked(() => {
		let frame={identity:i.load('identity.json'),state:i.load('cluster.json'),local:i.load('state.json'),
			boot:i.boot(),now:i.now(),key:detail ? i.read('device.key') : null};
		// Enrollment observations use the exact same native monotonic clock as
		// their worker. The existing protocol uptime clock keeps its own scope.
		if(i.enrollment_now)frame.enrollment_now=i.enrollment_now();
		return frame;
	},5);
}
function captured_pair(i, frame) {
	return pairing_service({
		load: name => name == 'identity.json' ? frame.identity : name == 'cluster.json' ? frame.state : name == 'state.json' ? frame.local : null,
		read: name => name == 'device.key' ? frame.key : null,
		write: () => die('identity_error: Device identity is unavailable'),
		save: () => die('identity_error: Device identity is unavailable'),
		boot: () => frame.boot, now: () => frame.now,
		// Presence is volatile and read after releasing the private-frame lock.
		// Compare against a clock read after that observation, not the older frame.
		presence: i.presence, presence_now: i.presence_now, public_intent, public_active,
		public_enrollment: identity=>i.public_enrollment ? i.public_enrollment(identity,frame.boot,frame.enrollment_now ?? int(frame.now*1000)) : null
	});
}
export function frozen_cluster_status(i, view) {
	view = status_view(view);
	let full = view == 'full', frame = status_frame(i), pair = captured_pair(i, frame);
	// The captured identity and journal stay private while projection and telemetry run without the write lock.
	let result = pair.status(view), state = pair.state();
	if (full || index(['nodes', 'backhaul'], view) >= 0)
		for (let member in result.members) {
			let persisted = state?.members?.[member.id];
			let telemetry = member.authorized ? i.observed_report?.(member.id,
				{ controller_id: result.identity?.id, network_id: result.identity?.network_id,
					certificate: persisted?.certificate || null }, persisted?.report) : null;
			if (!telemetry || !member.report) continue;
			if (full) member.report.health = telemetry.health;
			if (member.report.backhaul) member.report.backhaul.quality = telemetry.quality;
		}
	if (full || index(['nodes', 'wireless', 'backhaul'], view) >= 0)
		result.lifecycle = public_lifecycle(state?.lifecycle, full ? null : false);
	if (full || view == 'history') {
		result.lifecycle_history = state?.lifecycle_history || [];
		result.metadata_history = map(state?.metadata_history || [],row=>({id:row.id,node_id:row.node_id,
			previous_name:row.previous_name,name:row.name,version:row.version,status:row.status,timestamp:row.timestamp}));
	}
	let identity = frame.identity;
	result.migration=identity?.role=='root' ? public_migration(state?.migration,full ? null : false) : public_migration(identity?.migration,false);
	result.local_repair = identity?.agent?.repair ? {
		id: identity.agent.transaction, status: identity.agent.status,
		transaction_id: identity.agent.transaction_id || null,
		manual: match(identity.agent.id || '', /^local-repair-/) != null
	} : null;
	result.local_mesh = identity?.agent?.mesh ? { transaction_id: identity.agent.transaction_id || null,
		manual: match(identity.agent.id || '', /^local-mesh-/) != null } : null;
	if (full || view == 'clients') {
		let observations = i.client_status();
		for (let member in result.members)
			member.clients = member.authorized && member.online && !member.mesh_paused && state.members[member.id]?.report?.mesh_enabled!==false ?
				observations.nodes[member.id] || [] : [];
		result.client_events = observations.events;
	}
	if (full || index(['overview', 'diagnostics'], view) >= 0) result.agent = i.agent_status();
	return result;
}
export function cluster_status(view) {
	return frozen_cluster_status({ ...durable, presence, presence_now: durable.now, observed_report,
		public_enrollment: enrollment_observation, enrollment_now:enrollment_uptime,
		client_status: client_events.status, agent_status: () => {
			try { return json(fs.readfile('/var/run/mesh-manager-agent.json') || 'null'); }
			catch (e) { return null; }
		} }, view);
}
export function history_records(group) {
	let field = { cluster: 'history', repair: 'repair_history', lifecycle: 'lifecycle_history', metadata:'metadata_history' }[group];
	if (!field) die('invalid_request: Unknown history group');
	let frame = status_frame(durable), pair = captured_pair(durable, frame);
	if (frame.identity?.role != 'root') die('not_controller: This node is not a Mesh controller');
	return pair.state()[field] || [];
}
export function frozen_status_detail(i, args) {
	if (index(['cluster', 'repair', 'lifecycle', 'migration'], args?.kind) < 0 ||
		type(args.id) != 'string' || !match(args.id, /^[a-zA-Z0-9_-]{16,96}$/))
		die('invalid_request: Invalid status detail request');
	let frame = status_frame(i, true), pair = captured_pair(i, frame);
	pair.root();
	let state = pair.state(), result;
	if (args.kind == 'migration') result=public_migration(state.migration);
	else if (args.kind == 'cluster') result = public_active(state.active);
	else if (args.kind == 'lifecycle') result = public_lifecycle(state.lifecycle);
	else {
		let member = state.members[args.node_id];
		if (!member?.authorized) die('not_authorized: Node is not authorized');
		result = public_repair(member.repair);
	}
	if (!result || result.id != args.id)
		die('preview_changed: Status details changed; refresh and review again');
	return result;
}
export function status_detail(args) { return frozen_status_detail(durable, args); }
function root_mesh(method, args) {
	let svc = services(), i = svc.io, pair = svc.pair, cluster = svc.cluster, data = i.load('identity.json');
	if (method == 'mesh_confirm') {
		let active = i.local.status().active, result;
		if (active?.mesh_enabled === false) result = cluster.lifecycle.confirm(args.transaction_id);
		else if (active?.mesh_enabled === true && active.id == args.transaction_id)
			result = i.local.confirm(args.transaction_id);
		else die('invalid_state: Mesh confirmation does not match the controller transaction');
		if (system(['/etc/init.d/mesh-manager', 'reload'], 5000) != 0)
			die('service_error: Mesh was confirmed but listener state needs a service reload');
		return result;
	}
	let state = pair.state();
	if (args.enabled !== true) die('ap_restore_required: Prepare all AP restores before stopping Root');
	if (lifecycle_busy(state) || configuration_busy(state, i))
		die('busy: A cluster operation is pending');
	let intent = controller_intent(state.intent, effective_settings(data, i.load('state.json')), data, state);
	if (method == 'mesh_preview') return i.local.mesh_preview(true, intent);
	let staged = i.local.mesh_stage(true, intent, args.request_id, args.takeover, args.approval);
	if (system(['/etc/init.d/mesh-manager', 'reload'], 5000) != 0)
		die('service_error: Controller listeners could not start; candidate will expire safely');
	return staged;
}
export function advanced_dispatch(method, args) {
	if (index(method,'migration_')==0) return durable.locked(()=>{
		let service=migration();
		if(method=='migration_status')return service.status();
		if(method=='migration_preflight')return service.preflight(args.node_id,args.request_id);
		if(method=='migration_apply')return service.apply(args.request_id,args.approval,args.takeover);
		if(method=='migration_cancel')return service.cancel(args.request_id);
		if(method=='migration_resume')return service.resume(args.request_id);
		die('invalid_method: Unknown migration method');
	});
	if(method!='onboard_status')require_authority(durable.load('identity.json'),durable.load('identity.json')?.role=='root' ? durable.load('cluster.json') : null);
	if (method == 'discover') {
		if (args.mode == 'wired') return discover(durable.load('identity.json'));
		if (args.mode == 'wireless')
			return discover_wireless(durable.load('identity.json'), null, null, null,
				args.timeout || 10);
		die('invalid_mode: Discovery mode must be wired or wireless');
	}
	if (method == 'onboard_status') return onboard_status();
	if (method == 'onboard_stop') return onboard_stop();
	if (method == 'enrollment_stop')
		return cancel_enrollment({ locked: durable.locked,
			identity_raw: () => { identity_service(io()).identity(); return durable.read('identity.json'); },
			cleanup_capture: onboard_cleanup_capture, cleanup_owned: onboard_stop_owned,
			cancel: () => {
				enrollment_service({ ...enrollment_io(), cleanup: () => {} }).stop();
				return enrollment_observation(durable.load('identity.json'), durable.boot(), int(durable.now()*1000));
			} });
	if (index(['mesh_preview','mesh_stage','mesh_confirm'], method) >= 0)
		return lifecycle_client({ ...io(), serialized:serialized_repair, root:root_mesh,
			request:(data, request) => agent_exchange(data.binding,
				{protocol:1,network_id:data.binding.network_id,...request},data) })(method,args);
	if (index(['repair_preview', 'repair_stage', 'repair_confirm', 'local_overrides_preview', 'local_overrides_stage', 'local_overrides_confirm'], method) >= 0) {
		let i = io();
		return repair_client({ ...i, serialized: serialized_repair, request: repair_target,
			probe: probe_managed, root: (method, args) => {
				let svc = services();
				if (index(method, 'local_overrides_') == 0) return root_settings(i, svc.pair, method, args);
				let repair = svc.cluster.repair;
				if (method == 'repair_preview') return repair.local_preview();
				if (method == 'repair_stage') return repair.local_stage(args.request_id, args.approval, args.takeover);
				return repair.local_confirm(args.transaction_id);
			} })(method, args);
	}
	return durable.locked(() => {
		let svc = services(),
			i = svc.io,
			pair = svc.pair,
			cluster = svc.cluster;
		if (method == 'enrollment_start') {
			let enrollment=enrollment_service(enrollment_io());
			enrollment.start(args);
			return enrollment_observation(durable.load('identity.json'),durable.boot(),int(durable.now()*1000));
		}
		if (method == 'controller_init' || method == 'setup_create') {
			if (args.takeover !== true)
				die('takeover_required: Explicit controller initialization required');
			validate_overrides(args.local);
			let previous_identity = i.load('identity.json');
			validate_controller_management(args.local,
				previous_identity?.role == 'root' ? previous_identity.address : args.address);
			if (previous_identity?.role == 'root' && args.address != previous_identity.address)
				validate_controller_management(args.local, args.address);
			if (method == 'setup_create' && (i.local.status().configured || pair.state().intent))
				die('already_configured: Enable the saved Mesh configuration instead');
			if (index(['router', 'bridge'], args.gateway) < 0) die('invalid_role: Invalid gateway role');
			let s = snapshot();
			validate_controller_management(args.local, args.address, s.network.lan?.values || {});
			let ids = identity_service(i),
				result = ids.root(args.name, args.address),
				identity = ids.identity();
			identity.gateway = args.gateway;
			identity.overrides = clone(args.local);
			i.save('identity.json', identity);
			if (system(['/etc/init.d/mesh-manager', 'reload'], 5000) != 0)
				die('service_error: Controller services could not start');
			if (method == 'setup_create') return cluster.preflight(args.intent, args.request_id, false);
			return result;
		}
		if (method == 'mesh_stop_prepare') return cluster.lifecycle.prepare(args.request_id);
		if (method == 'node_mesh_prepare') return cluster.lifecycle.node_prepare(args.node_id, args.enabled, args.request_id);
		if (method == 'mesh_stop_apply') return cluster.lifecycle.apply(args.request_id, args.approval, args.takeover);
		if (method == 'mesh_stop_cancel') return cluster.lifecycle.cancel(args.request_id);

		if (method == 'certificate_renew') return certificates.request(args.node_id);
		if (method == 'node_revoke') return pair.revoke(args.node_id);
		if (method == 'node_rename_preview') return pair.rename_preview(args.node_id,args.name);
		if (method == 'node_rename') return pair.rename(args);
		if (method == 'node_repair') return cluster.repair.enqueue(args.node_id, args.request_id);
		if (method == 'node_repair_apply')
			return cluster.repair.apply(args.node_id, args.request_id, args.approval, args.takeover);
		if (method == 'node_repair_rollback') return cluster.repair.rollback(args.node_id, args.request_id);
		if (method == 'cluster_preflight')
			return cluster.preflight(args.intent, args.request_id, args.maintenance);
		if (method == 'cluster_apply')
			return cluster.apply(args.transaction_id, args.approval, args.takeover);
		if (method == 'cluster_rollback') return cluster.rollback(args.transaction_id);
		if (method == 'local_overrides') {
			settings_context(i.load('identity.json'), i.load('state.json'), args.local);
			die('preview_required: Preview and apply local settings through a guarded transaction');
		}
		die('invalid_method: Unsupported cluster method');
	});
}
export function peer_request(identity, mode, request, source, destination, certificate) {
	return durable.locked(() => {
		if (index(['enroll','node'],mode)<0) die('invalid_transport: Unknown controller listener');
		if (mode != 'enroll') validate_request(request);
		let svc = services(),
			pair = svc.pair,
			cluster = svc.cluster;
		let local_identity=durable.load('identity.json'),migration_state=pair.state()?.migration;
		if (mode=='enroll') {require_authority(local_identity,pair.state());return pair.enroll(request, source);}
		// Completed migrations may still need to drain an AP poll receipt.
		// Ordinary AP requests retain the normal certificate and ingress checks.
		if(migration_state && (index(['complete','cancelled','expired'],migration_state.phase)<0 ||
			request.action=='migration_status' || request.action=='poll' && migration_state.phase=='complete' && request.report?.migration?.phase!='complete')) {
			let migrated=migration().peer(identity,request,certificate,destination);
			if(migrated!=null) {
				let roster=anchor_roster(local_identity,pair.state(),identity,crypto.fingerprint(durable.read('device.crt')));
				if(roster!=null)migrated.anchor_roster=roster;
				return seal(request,migrated,identity,{load:durable.load,read:durable.read,time});
			}
		}
		if(local_identity.role!='root')die('not_controller: Only the active controller accepts configuration requests');
		let member=pair.state().members[identity];
		if (certificate != null && certificate!=member?.certificate &&
			(member?.authorized!==true || certificate!=member.certificate_successor))
			die('not_authorized: Node certificate is no longer authorized');
		let access=control_ingress(durable.load('identity.json'),pair.state(),identity,request,
			destination,durable.boot(),durable.now());
		let reply=ingress_response(access,cluster.peer(identity, request));
		if(member?.authorized===true && request.action=='poll' && request.credentials!=null)
			reply.credentials=certificates.peer(identity,certificate,request.credentials);
		let roster=anchor_roster(local_identity,pair.state(),identity,crypto.fingerprint(durable.read('device.crt')));
		if(roster!=null)reply.anchor_roster=roster;
		if (access.pin) {
			let state=pair.state();
			if (state.members[identity].control_bound!==true) {
				state.members[identity].control_bound=true;durable.save('cluster.json',state);
			}
		}
		return seal(request,reply,identity,{load:durable.load,read:durable.read,time});
	});
}
export function agent_tick() {
	let data = durable.load('identity.json');
	if (!data) return;
	if (data.departing) { ap_agent_tick(); return; }
	if (data.role == 'root') {
		let moving=durable.load('cluster.json')?.migration;
		if(moving && index(['complete','cancelled','expired'],moving.phase)<0 || data.authority_fence) {
			let service=migration();durable.locked(()=>service.tick_locked());service.handover();return;
		}
		durable.locked(() => services().cluster.tick());
		durable.locked(() => certificates.root_tick());
		try {
			let local = durable.load('state.json');
			let sample = local?.intent && !local.paused ? observe_clients(local.intent) : null, clients = client_events.sanitize_clients(sample?.clients);
			if (sample?.complete && length(clients) == length(sample.clients))
				durable.locked(() => client_events.observe(data.id, clients));
		} catch (e) {
			// Terminal telemetry must not stop configuration recovery.
		}
		let state = durable.load('state.json'), pending = state?.active;
		if (state?.paused === true && (pending?.mesh_enabled !== true ||
			index(['committed','rolled_back','rollback_conflict','expired'], pending.status) >= 0) &&
			fs.access('/var/run/mesh-manager-listening'))
			system(['/etc/init.d/mesh-manager', 'reload'], 5000);
		return;
	}
	if (data.joining) {
		// Automatic enrollment has one existing worker and one absolute retry
		// budget; the ordinary agent must not issue a second simultaneous poll.
		if (data.role != 'unbound' || data.enrollment?.enabled !== true)
			services().pair.join_tick();
		return;
	}
	ap_agent_tick();
}
