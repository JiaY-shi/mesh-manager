// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { equal, clone } from './model.uc';
import { contact_binding } from './controller_contact.uc';
import { identifier } from 'mesh_crypto';

export const CONTROLLER_LOSS_TIMEOUT=300;
export function loss_timeout(value) {
	return type(value)=='int' && value>=60 && value<=3600 ? value : CONTROLLER_LOSS_TIMEOUT;
}
export function loss_frame(identity, state, contact, watch, boot, now, timeout) {
	if (identity?.role!='ap' || !identity.binding || !state?.intent || state.paused===true) return null;
	if (index(['int','double'],type(now))<0 || now<0 || type(boot)!='string')
		die('clock_error: Controller loss clock is unavailable');
	let scope={boot,id:identity.id,binding:clone(identity.binding),version:state.version};
	let valid=watch && equal(watch.scope,scope) && index(['int','double'],type(watch.started))>=0 &&
		watch.started>=0 && watch.started<=now;
	let started=valid ? watch.started : now, last=started;
	if (contact?.boot==boot && equal(contact.binding,contact_binding(identity.binding)) &&
		index(['int','double'],type(contact.uptime))>=0 && contact.uptime>=0 && contact.uptime<=now)
		last=max(last,contact.uptime);
	let deadline=last+loss_timeout(timeout);
	return {scope,started,last,deadline,due:now>=deadline,
		retry:valid && watch.retry>now ? watch.retry : null};
}

export function loss_monitor(io) {
	return () => {
		let frame=io.capture();
		if (frame.identity?.role!='ap' || !frame.identity.binding || !frame.state?.intent || frame.state.paused===true) return null;
		let now=io.now(),watch=io.read_watch(),
			current=loss_frame(frame.identity,frame.state,io.read_contact(),watch,io.boot(),now,io.timeout());
		if (!current) return null;
		if (!watch || !equal(watch.scope,current.scope) || watch.started!==current.started)
			io.write_watch({scope:current.scope,started:current.started});
		if (!current.due || current.retry!=null) return {status:'watching',remaining:max(0,int(current.deadline-now))};
		try {
			let result=io.restore(current);
			io.write_watch({scope:current.scope,started:current.started,retry:now+(result?.status=='rolling_back' ? 2 : 60)});
			return {status:result?.status || 'restoring',remaining:0};
		} catch(e) {
			io.write_watch({scope:current.scope,started:current.started,retry:now+60});
			die(e.message || ''+e);
		}
	};
}

export function recovery_path(path) {
	if (type(path)!='string' || length(path)>196) return false;
	let parts=split(path,'.');
	return length(parts)==3 && index(['network','wireless','dhcp','firewall','usteer'],parts[0])>=0 &&
		identifier(parts[1]) && (parts[2]=='@section' || identifier(parts[2]));
}
export function recovery_report(value) {
	if (type(value)!='object' || value.cause!='controller_lost' ||
		!match(value.request_id || '',/^controller-lost-[0-9a-f]{32}$/) ||
		type(value.transaction_id)!='string' || length(value.transaction_id)<16 || length(value.transaction_id)>64 ||
		index(['staged','apply_requested','applying','awaiting_confirm','committed','rollback_requested',
			'rolling_back','rolled_back','rollback_conflict','expired'],value.status)<0 ||
		type(value.conflicts)!='array' || length(value.conflicts)>512 ||
		length(filter(value.conflicts,item=>type(item)!='object' || !recovery_path(item.path)))) return null;
	return {cause:'controller_lost',request_id:value.request_id,transaction_id:value.transaction_id,
		status:value.status,health_confirmed:value.health_confirmed===true,
		conflicts:map(value.conflicts,item=>({path:item.path,message:'External change preserved; manual recovery required'}))};
}
export function loss_receipt(report) {
	let recovery=recovery_report(report?.controller_recovery),tx=report?.transaction;
	return recovery && recovery.status=='committed' && recovery.health_confirmed===true && !length(recovery.conflicts) &&
		tx?.cause=='controller_lost' && tx.id==recovery.transaction_id && tx.request_id==recovery.request_id;
}
