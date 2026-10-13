// SPDX-License-Identifier: GPL-2.0-only
'use strict';

// Mesh disable keeps the AP's control agent for reporting and remote re-enable.
// An unbound, idle device has no dedicated process. Shared OpenWrt services are
// outside this policy. Unknown state retains recovery rather than stopping it.
export function service_policy(identity,state,temporary,demand,cluster) {
	let roles=['unbound','root','ap'],final=['committed','rolled_back','expired'],
		unknown=identity!=null && (identity.schema!==1 || index(roles,identity.role)<0) ||
			state!=null && (state.schema!==1 || type(state.owned)!='array' || type(state.history)!='array'),
		pending=state?.active!=null && index(final,state.active.status)<0 ||
			state?.intent==null && length(state?.owned || [])>0 ||
			identity?.role=='root' && length(filter([cluster?.active,cluster?.lifecycle],job=>job!=null &&
				index(['complete','partial','failed','rolled_back','cancelled','expired'],job.phase)<0))>0,
		enabled=state?.intent!=null && state.paused!==true,
		enrolling=identity?.enrollment?.enabled===true,
		joining=identity?.joining!=null,
		bound=identity?.role=='ap' && identity.binding!=null,
		root=identity?.role=='root',
		recovery=unknown || pending || temporary || demand || enabled || enrolling || joining || bound || identity?.departing!=null,
		agent=unknown || bound || joining && !enrolling || root && (enabled || pending),
		backhaul=unknown || enabled || pending,
		listener=root && (enabled || pending || demand),instances=[];
	if(recovery)push(instances,'instance1');
	if(enrolling || temporary)push(instances,'enrollment');
	if(backhaul)push(instances,'backhaul');
	if(agent)push(instances,'agent');
	if(listener)for(let name in ['node','enroll','control'])push(instances,name);
	return {instances,mode:!length(instances)?'stopped':unknown || pending || temporary && !bound?'recovery':
		enrolling || joining?'joining':enabled?'active':bound?'standby':'starting'};
}

// Desired policy is not evidence that procd has finished changing instances.
// Projection is observational and never wakes or stops a service.
export function observed_background(desired, actual) {
	if (type(actual) != 'object') return {mode:'unknown', instances:null};
	let names=keys(actual), running=filter(names,name=>actual[name]?.running===true);
	if (desired.mode=='stopped') return {mode:length(names) ? 'stopping' : 'stopped', instances:running};
	let complete=length(names)==length(desired.instances) && !length(filter(names,name=>
		index(desired.instances,name)<0 || actual[name]?.running!==true));
	return {mode:complete ? desired.mode : 'adjusting', instances:running};
}
