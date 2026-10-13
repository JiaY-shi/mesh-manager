// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal, valid_text, public_enrollment } from './model.uc';
import { private_address } from './identity.uc';
import { joining_code } from './invitation.uc';
import { enrollment_hints } from './enrollment_progress.uc';

// Keep the actor's original authority intact until its owned transport is
// gone. Retiring identity first makes the actor self-clean concurrently with
// the explicit stop. Never hold the durable lock across that external wait.
export function cancel_enrollment(io) {
	let frame = io.locked(() => {
		let raw = io.identity_raw();
		if (json(raw)?.role != 'unbound')
			die('already_bound: Disable the configured Mesh to restore this AP');
		return { raw, owner: io.cleanup_capture() };
	});
	if (frame.owner && !io.cleanup_owned(frame.owner))
		die('cleanup_conflict: Original cancelled transport was preserved');
	return io.locked(() => {
		if (io.identity_raw() !== frame.raw)
			die('preview_changed: Enrollment changed while stopping its temporary transport');
		return io.cancel();
	});
}

export function enrollment_service(io) {
	function start(args) {
		let data = io.identity();
		if (data.role != 'unbound' || data.binding) die('already_bound: Complete or cancel enrollment first');
		if (args.takeover !== true) die('takeover_required: Automatic AP enrollment requires consent');
		if (!valid_text(args.name, 1, 64)) die('invalid_name: Invalid node name');
		io.validate_overrides(args.local);
		if (args.code) joining_code(args.code);
		if (args.ssid && (!valid_text(args.ssid, 1, 32) || type(args.password) != 'string' ||
			length(args.password) < 8 || length(args.password) > 63))
			die('invalid_wireless: Wireless enrollment needs Wi-Fi credentials');
		// Explicitly reconnect the same pending wireless request after its
		// temporary actor expires. Its identity, invitation and credentials stay
		// unchanged; an approved or different request cannot be replaced here.
		let previous = data.enrollment, resuming = data.joining == null && previous?.resume != null;
		if (resuming) data.joining = clone(previous.resume);
		let joining = data.joining, pending = joining != null,
			wired_pending = previous?.phase == 'wired' || resuming && previous.resume_phase == 'wired';
		if (pending && (index(['requesting','pending'], joining.status) < 0 || joining.approval != null ||
			!args.ssid && !wired_pending || args.code && args.code !== 'MM1:' + joining.invitation.address + ':' +
			joining.invitation.fingerprint + ':' + joining.invitation.token ||
			args.name !== data.name || !equal(args.local, data.overrides)))
			die('already_bound: Complete or cancel enrollment first');
		if(args.bssid && !match(args.bssid,/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/) ||
			args.device && !match(args.device,/^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/))die('invalid_wireless: Invalid scanned access point');
		let target=args.candidate?.address ? args.candidate : null;
		if(target && (!private_address(target.address) || !match(target.fingerprint || '',/^[0-9a-f]{64}$/)))die('identity_error: Invalid controller selection');
		let requested_code=args.code || (pending ? 'MM1:'+joining.invitation.address+':'+joining.invitation.fingerprint+':'+joining.invitation.token : null);
		if(previous?.enabled===true && previous.name==args.name && equal(previous.local,args.local) &&
			previous.code==requested_code && previous.ssid==(args.ssid || null) &&
			previous.password==(args.ssid ? args.password : null) && previous.bssid==(args.bssid || null) &&
			previous.device==(args.device || null) && equal(previous.target || null,target ? {address:target.address,fingerprint:target.fingerprint} : null))return public_enrollment(previous);
		data.enrollment = { enabled: true, epoch: io.random(16), status: pending ? 'pending' : 'searching_wired',
			phase: pending && args.ssid ? 'wireless' : 'wired', boot: io.boot(), next: 0, cycle: 0, code: requested_code,
			name: args.name, local: clone(args.local), ssid: args.ssid || null,
			password: args.ssid ? args.password : null, bssid: args.bssid || null, device: args.device || null, target: target ? {address:target.address,fingerprint:target.fingerprint} : null, candidates: [], access_points: [] };
		io.save_identity(data); return public_enrollment(data.enrollment);
	}
	function stop() {
		let data = io.identity();
		if (data.role != 'unbound') die('already_bound: Disable the configured Mesh to restore this AP');
		if (data.enrollment?.enabled !== true) return public_enrollment(data.enrollment);
		if (data.enrollment) {
			// An automatic Root may already have issued this device's certificate.
			// Keep only the private request identity for the next explicit start;
			// erasing it would strand the same device as already_registered.
			let resume = index(['requesting','pending'], data.joining?.status) >= 0 ? clone(data.joining) : null,
				phase = data.enrollment.phase;
			if (resume) { delete resume.approval; delete resume.error; resume.status = 'pending'; }
			data.enrollment = { enabled: false, epoch: io.random(16), status: 'stopped', cycle: data.enrollment.cycle || 0,
				...(resume ? {resume, resume_phase:phase} : {}) };
			data.joining = null;
			io.save_identity(data);
		}
		io.cleanup(); return public_enrollment(io.identity().enrollment);
	}
	function tick() {
		let data=io.load_identity(),instruction=data?.enrollment;
		if(!instruction?.enabled)return;
		// Persistent semantic transitions stay explicit; progress never uses this
		// boundary or durable.save, even if tmpfs is missing or full.
		if(data.role=='ap') {
			if(io.managed())io.boundary(data,d=>{d.enrollment={...d.enrollment,enabled:false,status:'joined',
				error:null,code:null,password:null,ssid:null};});
			return;
		}
		if(data.role!='unbound')return;
		if(data.joining) {
			if(data.joining.status=='rejected')io.cancel_attempt?.(data);
			else if(index(['requesting','pending'],data.joining.status)>=0)io.resume_tick?.(data);
			return;
		}
		let frame=io.progress.begin(data);if(!frame)return;
		function update(patch) { return io.progress.commit(frame,patch); }
		let p=frame.progress,e={...instruction,...p,next:p.next_uptime_ms/1000};
		if(io.now()<e.next)return;
		if(e.phase=='wired') {
			if(!update({status:'searching_wired',cycle:e.cycle+1,error:null,next:0}) || !io.progress.check(frame))return;
			let discovered=io.wired(),candidates=enrollment_hints(filter(discovered.candidates || [],c=>!c.binding_conflict),[]).candidates;
			if(!update({candidates,error:discovered.error || null}))return;
			if(e.target)candidates=filter(candidates,c=>c.address==e.target.address && c.fingerprint==e.target.fingerprint);
			if(e.code) {
				let pinned=joining_code(e.code);
				candidates=filter(candidates,c=>c.address==pinned.address && c.fingerprint==pinned.fingerprint);
			}
			if(length(candidates)==1 && io.progress.check(frame)) {
				try {if(io.join_wired(frame,candidates[0],instruction))return;}
				catch(error){if(!update({error:match(error.message || '',/^([a-z_]{1,32}):/)?.[1] || 'peer_unavailable'}))return;}
			}
			update({phase:'wireless',status:length(candidates)>1 ? 'select_controller' : 'searching_wireless',next:0});return;
		}
		if(!update({status:'searching_wireless',next:0}) || !io.progress.check(frame))return;
		let scan=io.wireless(),points=enrollment_hints([],scan.access_points || []).access_points;
		if(!update({access_points:points}))return;
		if(e.ssid && io.progress.check(frame)) {
			let choices=filter(points,ap=>ap.ssid==e.ssid && (!e.bssid || ap.bssid==e.bssid) && (!e.device || ap.device==e.device));
			for(let chosen in choices) {
				try{if(io.join_wireless(frame,chosen,instruction))return;}
				catch(error){
					let code=match(error.message || '',/^([a-z_]{1,32}):/)?.[1] || 'onboarding_failed';
					if(!update({error:code}))return;
					if(index(['channel_conflict','unsupported_radio'],code)<0)break;
				}
			}

		}
		update({phase:'wired',status:'waiting_retry',next:io.now()+30});
	}
	return { start, stop, tick };
}
