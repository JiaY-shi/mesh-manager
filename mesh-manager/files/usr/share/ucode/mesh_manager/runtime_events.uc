// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { sha256 } from 'mesh_crypto';
import { equal } from './model.uc';

const COMPONENTS=['local','cluster','identity','recovery','agent','backhaul'];
const STATES=['unknown','no_change','enabled','disabled','preparing','root_applying','requesting','error',
	'idle','ok','unbound','root','ap','staged','preflight','ready','applying','apply_requested',
	'awaiting_confirm','confirming','committed','complete','partial','failed','rolling_back','rollback_requested',
	'rolled_back','rollback_conflict','expired','cancelled','queued','pending','rejected','approved','joined','stopped',
	'searching_wired','searching_wireless','waiting_retry','waiting_authorization','select_controller','configuring',
	'busy','clock_error','storage_error','corrupt_state','configuration_error','ownership_conflict','write_error',
	'reload_error','entropy_error','connection_error','timeout','path_block_failed','internal_error'];
function valid_number(value) { return type(value)=='int' && value>=0 && value<=2147483647; }
export function event_summary(component,status,version) {
	if(index(COMPONENTS,component)<0)die('invalid_request: Unknown runtime log component');
	return {component,status:index(STATES,status)>=0 ? status : 'unknown',version:valid_number(version) ? version : null};
}
export function runtime_events(io) {
	function read() {
		let raw=io.read(),state;
		if(raw==null)state={schema:1,boot:io.boot(),sequence:0,records:[],states:{},last_clear:null};
		else try{if(type(raw)!='string' || length(raw)>65536)die('oversized');state=json(raw);}catch(e){die('log_unavailable: Runtime log is corrupt');}
		if(state?.schema!=1 || state.boot!=io.boot() || !valid_number(state.sequence) || type(state.records)!='array' ||
			length(state.records)>128 || type(state.states)!='object' || length(keys(state.states))>length(COMPONENTS))
			die('log_unavailable: Runtime log structure is invalid');
		for(let component,item in state.states)
			if(index(COMPONENTS,component)<0 || !equal(item,event_summary(component,item?.status,item?.version)))
				die('log_unavailable: Runtime log component state is invalid');
		let last=state.last_clear;
		if(last!=null && (type(last)!='object' || length(keys(last))!=4 ||
			!match(last.request_id || '',/^[0-9a-f]{32}$/) || !match(last.owner || '',/^[0-9a-f]{64}$/) ||
			!match(last.expected || '',/^[0-9a-f]{64}$/) || !valid_number(last.count) || last.count>128))
			die('log_unavailable: Runtime log clear receipt is invalid');
		let previous=0;
		for(let row in state.records) {
			if(type(row)!='object' || length(keys(row))!=6 || !valid_number(row.sequence) || row.sequence<=previous ||
				row.sequence>state.sequence || row.id!=''+row.sequence || type(row.timestamp)!='int' || row.timestamp<0 || row.timestamp>4102444800 ||
				!equal(event_summary(row.component,row.status,row.version),{component:row.component,status:row.status,version:row.version}))
				die('log_unavailable: Runtime log record is invalid');
			previous=row.sequence;
		}
		return {state,revision:sha256(sprintf('%J',state))};
	}
	function write(state) {
		let text=sprintf('%J',state);
		if(length(text)>65536)die('quota_exceeded: Runtime log size limit reached');
		io.write(text);
	}
	return {
		read:()=>{let r=read();return {records:r.state.records,revision:r.revision};},
		append:(component,status,version)=>io.lock(()=>{
			let item=event_summary(component,status,version),r=read(),s=r.state;
			if(equal(s.states[component],item))return false;
			if(s.sequence>=2147483647)die('quota_exceeded: Runtime log sequence limit reached');
			s.sequence++;s.states[component]=item;
			push(s.records,{...item,id:''+s.sequence,sequence:s.sequence,timestamp:io.wall()});
			if(length(s.records)>128)shift(s.records);
			write(s);return true;
		}),
		clear:(expected,request_id,sid)=>io.lock(()=>{
			if(type(expected)!='string' || !match(expected,/^[0-9a-f]{64}$/) ||
				type(request_id)!='string' || !match(request_id,/^[0-9a-f]{32}$/) ||
				type(sid)!='string' || !match(sid,/^[0-9a-f]{32}$/))die('invalid_request: Invalid runtime log clear request');
			let r=read(),s=r.state,owner=sha256(sid),last=s.last_clear;
			if(last?.request_id==request_id) {
				if(last.owner!=owner || last.expected!=expected)die('request_reused: Clear request belongs to another operation');
				return {cleared:last.count,replayed:true};
			}
			if(r.revision!=expected)die('preview_changed: Runtime logs changed; reload before clearing');
			let count=length(s.records);s.records=[];
			s.last_clear={request_id,owner,expected,count};
			write(s);return {cleared:count,replayed:false};
		})
	};
}
