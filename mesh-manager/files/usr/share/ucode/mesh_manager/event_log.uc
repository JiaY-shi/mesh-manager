// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import { runtime_events, event_summary } from './runtime_events.uc';

const DIRECTORY='/var/run/mesh-manager-events',FILE=DIRECTORY+'/events.json',TEMP=FILE+'.new';
let remembered={};
function safe(path,kind,optional) {
	let st=fs.lstat(path);
	if(!st && optional)return null;
	if(st?.type!=kind || st.uid!=0 || st.mode&0077 || kind=='file' && st.size>65536)
		die('log_unavailable: Unsafe runtime log storage');
	return st;
}
function directory(create) {
	if(!fs.lstat(DIRECTORY)) {
		if(!create)return false;
		if(!fs.mkdir(DIRECTORY,0700) && !fs.lstat(DIRECTORY))die('log_unavailable: Cannot create runtime log storage');
	}
	safe(DIRECTORY,'directory');return true;
}
function boot() {
	let id=trim(fs.readfile('/proc/sys/kernel/random/boot_id') || '');
	if(!match(id,/^[0-9a-f-]{36}$/))die('log_unavailable: Runtime log boot identity unavailable');
	return id;
}
const events=runtime_events({boot,wall:()=>time(),
	read:()=>{
		if(!directory(false) || !safe(FILE,'file',true))return null;
		let value=fs.readfile(FILE);if(type(value)!='string')die('log_unavailable: Cannot read runtime log');
		return value;
	},
	write:text=>{
		// All writers hold the private lock. A previous crash may leave a bounded
		// private temporary file; neither a link nor a foreign file is removed.
		if(safe(TEMP,'file',true) && !fs.unlink(TEMP))die('log_unavailable: Cannot clear interrupted temporary log');
		let f=fs.open(TEMP,'wx',0600);
		if(!f)die('log_unavailable: Cannot stage runtime log');
		let ok=f.write(text)==length(text) && f.flush();f.close();
		if(!ok || !fs.rename(TEMP,FILE))die('log_unavailable: Cannot publish runtime log');
	},
	lock:callback=>{
		directory(true);safe(DIRECTORY+'/lock','file',true);
		let f=fs.open(DIRECTORY+'/lock','ae',0600);
		if(!f?.lock('xn')) {f?.close();die('busy: Runtime log is being updated');}
		try{let result=callback();f.close();return result;}catch(e){f.close();die(e.message || ''+e);}
	}
});
export function event_read() { return events.read(); }
export function event_clear(expected,request_id,sid) { return events.clear(expected,request_id,sid); }
export function note(component,status,version,check_shared) {
	try {
		let item=event_summary(component,status,version),signature=sprintf('%J',item);
		if(!check_shared && remembered[component]==signature)return true;
		events.append(component,status,version);remembered[component]=signature;return true;
	} catch(e) {
		// Diagnostic records must never turn a successful durable write into an
		// apparent configuration failure, or prevent independent recovery.
		return false;
	}
}
export function note_state(name,state) {
	if(type(state)!='object')return false;
	// Several processes can save the same journal. Compare the shared last state
	// after a durable write; an in-process cache could miss another writer's change.
	if(name=='state.json')return note('local',state.active?.status || 'idle',state.version,true);
	if(name=='cluster.json')return note('cluster',state.active?.phase || 'idle',state.active?.version ?? state.version,true);
	if(name=='identity.json')return note('identity',state.agent?.status || state.enrollment?.status || state.role,state.cluster_version,true);
}
