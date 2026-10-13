// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { cursor } from 'uci';
import * as durable from './durable.uc';
import { locked, read_locked } from './runtime.uc';
import { equal } from './model.uc';
import { contact_read, contact_write } from './controller_contact.uc';
import { loss_monitor, loss_frame, loss_timeout } from './controller_loss.uc';

function capture() {
	let identity=durable.load('identity.json');
	return {identity,state:identity?.role=='ap' && identity.binding ? read_locked(()=>durable.load('state.json'),5) : null};
}
export function controller_loss_timeout() {
	let c=cursor('/etc/config','/var/run/mesh-manager-uci','');c.load('mesh-manager');
	return loss_timeout(int(c.get('mesh-manager','main','controller_loss_timeout')));
}
const monitor=loss_monitor({capture,now:durable.now,boot:durable.boot,timeout:controller_loss_timeout,
	read_watch:()=>contact_read(true),read_contact:()=>contact_read(),
	write_watch:value=>contact_write(value,true),
	restore:original=>durable.locked(()=>locked(service=>{
		let identity=durable.load('identity.json'),state=durable.load('state.json'),
			current=loss_frame(identity,state,contact_read(),contact_read(true),durable.boot(),durable.now(),controller_loss_timeout());
		if (!current?.due || !equal(current.scope,original.scope)) return {status:'watching'};
		let active=state.active;
		if (active && index(['committed','rolled_back','rollback_conflict','expired'],active.status)<0) {
			// A slow pending configuration never blocks LAN recovery indefinitely.
			// Finish its existing CAS rollback before beginning another transaction.
			if (active.kind=='release' && active.local_confirmation===true) return {status:'restoring'};
			service.rollback(active.id);return {status:'rolling_back'};
		}
		let request='controller-lost-'+durable.random(16),staged=service.controller_lost_stage(request);
		service.apply(staged.id);return {status:'restoring'};
	},5),5)
});
let next=0;
export function controller_loss_tick() {
	let clock=durable.now();if (clock<next) return null;
	next=clock+5;return monitor();
}
