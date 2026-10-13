// SPDX-License-Identifier: GPL-2.0-only
'use strict';
'require mesh_manager.history as historyPages';
'require baseclass';
'require rpc';
'require ui';
'require mesh_manager.widgets as widgets';
'require mesh_manager.slow_rpc as slow_rpc';

var methods = {}, previewRequested = null, watchedJob = null, watchedLocal = null;
[['mesh_preview',['enabled']], ['mesh_stage',['enabled','request_id','approval','takeover']],
 ['mesh_stop_prepare',['request_id']], ['mesh_stop_apply',['request_id','approval','takeover']],
 ['node_mesh_prepare',['node_id','enabled','request_id']],
 ['status_detail',['kind','node_id','id']],
 ['mesh_stop_cancel',['request_id']], ['apply',['transaction_id']]].forEach(function(spec) {
	methods[spec[0]] = rpc.declare({object:'mesh-manager',method:spec[0],params:spec[1],reject:true});
});
methods.mesh_preview=function(enabled) { return slow_rpc.action('mesh_preview',{enabled:enabled}); };
methods.mesh_stage=function(enabled,request_id,approval,takeover) {
	return slow_rpc.action('mesh_stage',{enabled:enabled,request_id:request_id,approval:approval,takeover:takeover});
};
function call(method) {
	return methods[method].apply(null,Array.prototype.slice.call(arguments,1)).then(function(result) {
		if (!result || !result.ok) {
			var error=new Error(result && result.error && result.error.message || _('Backend unavailable')); error.code=result && result.error && result.error.code;
			if(method==='mesh_stage' && ['request_timeout','backend_unavailable'].indexOf(error.code)>=0)error.code='outcome_unknown';
			throw error;
		}
		return result.data;
	});
}
function retryBusy(method,args,attempt) {
	attempt=attempt || 0;
	return call.apply(null,[method].concat(args)).catch(function(error) {
		if(error.code!=='busy' || attempt>=4)throw error;
		return new Promise(function(resolve){window.setTimeout(resolve,250*(attempt+1));}).then(function(){return retryBusy(method,args,attempt+1);});
	});
}
function requestId() { var bytes=new Uint8Array(16);window.crypto.getRandomValues(bytes);return Array.from(bytes).map(function(b){return b.toString(16).padStart(2,'0');}).join(''); }
function button(label,action,disabled) { return E('button',{'class':'cbi-button cbi-button-neutral',type:'button',disabled:disabled || null,click:ui.createHandlerFn(null,action)},[label]); }
function notify(error) { ui.addNotification(null,E('p',{},[widgets.configurationError(error)]),'error'); }
function label(state) {
	return ({preparing:_('Preparing'),pending:_('Waiting for AP'),ready:_('Ready'),applying:_('Applying'),
		root_applying:_('Restoring this device'),awaiting_confirm:_('Awaiting confirmation'),confirming:_('Confirming'),
		staged:_('Staged'),committed:_('Committed'),disabled:_('Disabled'),enabled:_('Enabled'),complete:_('Complete'),failed:_('Failed'),partial:_('Partially completed'),
		cancelled:_('Cancelled'),rolled_back:_('Rolled back'),rollback_conflict:_('Rollback conflict'),expired:_('Expired'),unverified:_('Could not verify')})[state] || state;
}
function terminal(phase) { return ['complete','failed','partial','cancelled','expired'].indexOf(phase)>=0; }
function resultMessage(enabled) { return enabled ? _('Mesh is enabled.') : _('Mesh is disabled. Original managed settings have been restored.'); }
function queued() { ui.addNotification(null,E('p',{},[_('Mesh operation queued. Waiting for configuration and health checks.')])); }
function state(data) {
	var active=data.active, job=data.cluster && data.cluster.lifecycle;
	if(active && active.mesh_enabled!=null && ['committed','rolled_back','rollback_conflict','expired'].indexOf(active.status)<0) {
		var message=['rollback_requested','rolling_back'].indexOf(active.status)>=0 ? _('Rolling back Mesh change') :
			active.status==='awaiting_confirm' ? active.mesh_enabled ? _('Enable pending confirmation') : _('Disable pending confirmation') :
			active.mesh_enabled ? _('Enabling Mesh') : _('Disabling Mesh');
		return widgets.status(message,'warning');
	}
	if(job && !job.node_id && !terminal(job.phase))return widgets.status(_('Preparing to disable Mesh'),'warning');
	return widgets.status(data.mesh_enabled ? _('Mesh is enabled.') : _('Mesh is disabled.'),data.mesh_enabled ? 'good' : 'neutral');
}
function planBody(plan) {
	var changes=E('div',{'class':'mm-plan-diff'},[widgets.table([_('Setting'),_('Before'),_('After')],(plan.ops || []).filter(function(op){return op.changed!==false;}).map(function(op) {
		return [widgets.setting(op),op.before,op.after];
	}),_('No changed fields'))]);
	var body = [E('ul',{},(plan.errors || []).map(function(error) {
		var message = error.code==='restore_dhcp_conflict' ? _('Restoring DHCP on the connected uplink is unsafe. Disconnect that cable or move it to the original WAN port, then preview again.') :
			error.code==='restore_link_unknown' || error.code==='restore_topology_unknown' ? _('The original network or uplink state cannot be verified. Check the wiring and network configuration, then preview again.') :
			error.code==='ownership_conflict' ? _('External changes must be reviewed before restoring the original settings.') : widgets.configurationError(error);
		return E('li',{'class':'mm-error'},[message]);
	})),(plan.errors || []).length ? widgets.details(_('Technical details'),[changes]) : changes];
	if (plan.restore_recheck === true) body.unshift(E('p', { 'class': 'mm-muted' },
		_('Original settings have been restored. This operation only repeats health verification without changing configuration.')));
	return body;
}
function localPlanBody(data,plan) {
	var body=planBody(plan),network=(plan.ops || []).filter(function(op) {
		return op.config==='network' && op.section==='lan' && op.changed!==false &&
			['proto','ipaddr','netmask'].indexOf(op.option)>=0;
	});
	if(data.cluster.identity.role!=='ap' || !network.length)return body;
	var address=network.find(function(op){return op.option==='ipaddr';});
	var protocol=network.find(function(op){return op.option==='proto';});
	body.unshift(E('div',{'class':'alert-message warning mm-reconnect-notice','role':'note'},[
		E('p',{},[_('The management network will change. This page may disconnect. Reconnect from the resulting LAN network and confirm before the deadline; otherwise the device will roll back automatically.')]),
		E('p',{},[_('Resulting management address'),': ',protocol && protocol.after==='dhcp' ? _('Assigned by upstream DHCP; check the Root node list') :
			address && address.after!=null ? (Array.isArray(address.after)?address.after.join(', '):String(address.after)) : _('See the network changes below')]),
		E('p',{},[_('For remote AP shutdown, use the node button on Root. Root can verify and finish the change after the AP management address changes.')])
	]));
	return body;
}
function approve(title,body,perform,blocked,preview,cancel) {
	var consent=E('input',{type:'checkbox'}),sending=false;
	var apply=button(_('Apply'),function() {
		if (!consent.checked || sending || blocked) return;
		sending=true;apply.disabled=true;
		return perform().then(function(){ui.hideModal();}).catch(function(error){sending=false;consent.checked=false;apply.disabled=true;notify(error);});
	},true);
	consent.addEventListener('change',function(){apply.disabled=blocked || sending || !consent.checked;});
	widgets.modal(title,body.concat([E('label',{'class':'mm-approval'},[consent,' ',_('I approve the displayed configuration takeover')]),
		E('div',{'class':'mm-actions mm-dialog-actions'},[button(_('Cancel'),function(){
			if(sending)return;
			if(cancel)return cancel().then(function(){ui.hideModal();}).catch(notify);
			ui.hideModal();
		}),apply])]),preview);
}
function reviewStop(data,job,refresh,writable) {
	return call('status_detail','lifecycle','',job.id).then(function(current) {
		showStopReview(data,current,refresh,writable);
	}).catch(notify);
}
function showStopReview(data,job,refresh,writable) {
	var members=data.cluster.members || [],body=[];
	job.nodes.forEach(function(node) {
		var member=members.find(function(m){return m.id===node.id;});
		body.push(E('h4',{},[member && member.name || node.id]));
		if(node.plan)body=body.concat(planBody(node.plan));else body.push(E('p',{},[label(node.status)]));
	});
	if(job.root.plan)body.push(E('h4',{},[_('This device')])),body=body.concat(planBody(job.root.plan));
	approve(job.enabled ? _('Enable Mesh') : _('Disable Mesh and restore original settings'),body,function(){
		return call('mesh_stop_apply',job.id,job,true).then(function(){watchedJob=job.id;queued();return refresh();});
	},!writable || job.phase!=='ready',true,function(){return call('mesh_stop_cancel',job.id).then(refresh);});
}
function change(data,enabled,refresh,writable) {
	if(data.cluster.identity.role==='root' && !enabled)
		return call('mesh_stop_prepare',requestId()).then(function(job){previewRequested=job.id;return refresh();}).catch(notify);
	return call('mesh_preview',enabled).then(function(plan) {
		var request=requestId();
		approve(enabled ? _('Enable Mesh') : _('Disable Mesh and restore original settings'),localPlanBody(data,plan),function() {
			return retryBusy('mesh_stage',[enabled,request,plan,true]).then(function(staged){
				return retryBusy('apply',[staged.id]).then(function(){watchedLocal=staged.id;queued();return refresh();});
			});
		},!writable || (plan.errors || []).length>0,true);
	}).catch(notify);
}
function busy(data) {
	var job=data.cluster.lifecycle, active=data.cluster.active;
	return data.active && ['committed','rolled_back','rollback_conflict','expired'].indexOf(data.active.status)<0 ||
		job && ['complete','failed','partial','cancelled','expired'].indexOf(job.phase)<0 ||
		active && ['complete','partial','failed','rolled_back','expired'].indexOf(active.phase)<0;
}
function needsRestoreVerification(transaction) {
	return transaction && ['rolled_back','expired'].indexOf(transaction.status)>=0 &&
		(transaction.kind==='configure' && transaction.mesh_enabled===true ||
		 transaction.kind==='release' && transaction.restore_recheck===true && transaction.mesh_enabled===false);
}
function localAction(data,refresh,writable) {
	if(!data.configured)return null;
	var enabled=data.mesh_enabled===true, blocked=enabled && data.cluster.identity.role==='root' &&
		(data.cluster.members || []).some(function(n){return n.mesh_paused!==true || n.restoration_confirmed!==true || n.authorized && !n.online;});
	var action=button(enabled ? _('Disable Mesh') : _('Enable Mesh'),function(){return change(data,!enabled,refresh,writable);},!writable || !widgets.recoveryReady(data) || busy(data) || blocked);
	action.classList.add('mm-local-mesh');
	if(blocked)action.setAttribute('data-tooltip',_('Disable every AP first. Root can stop only after all APs confirm that Mesh is disabled.'));
	if (!enabled && data.cluster.identity.role==='ap' && needsRestoreVerification(data.active))
		return E('div',{'class':'mm-actions'},[action,button(_('Verify restoration'),function(){return change(data,false,refresh,writable);},
			!writable || !widgets.recoveryReady(data) || busy(data))]);
	return action;
}
function nodeAction(data,node,refresh,writable) {
	var target=node.mesh_paused===true,blocked=!writable || !data.mesh_enabled || !node.authorized || !node.online || !node.report || !node.report.configured || busy(data);
	var action=button(target ? _('Enable Mesh') : _('Disable Mesh'),function(){
		return call('node_mesh_prepare',node.id,target,requestId()).then(function(job){previewRequested=job.id;return refresh();}).catch(notify);
	},blocked);
	action.classList.add('mm-node-mesh');action.dataset.mmNode=node.id;
	if (target && node.restoration_confirmed===false && needsRestoreVerification(node.report && node.report.transaction)) {
		var verify=button(_('Verify restoration'),function(){
			return call('node_mesh_prepare',node.id,false,requestId()).then(function(job){previewRequested=job.id;return refresh();}).catch(notify);
		},blocked);
		verify.classList.add('mm-node-restore-verification');verify.dataset.mmNode=node.id;
		return E('div',{'class':'mm-actions'},[action,verify]);
	}
	return action;
}
function stopStatus(data,refresh,writable) {
	var job=data.cluster.lifecycle;
	if(watchedLocal && data.active && data.active.id===watchedLocal &&
		['committed','rolled_back','rollback_conflict','expired'].indexOf(data.active.status)>=0) {
		watchedLocal=null;
		ui.addNotification(null,E('p',{},[data.active.status==='committed' ? resultMessage(data.mesh_enabled) :
			_('Mesh operation did not complete. Check the rollback result.')]),data.active.status==='committed' ? 'info' : 'error');
	}
	if(job && watchedJob===job.id && terminal(job.phase)) {
		watchedJob=null;
		var member=(data.cluster.members || []).find(function(node){return node.id===job.node_id;});
		ui.addNotification(null,E('p',{},[(member ? member.name+': ' : '')+(job.phase==='complete' ? resultMessage(job.enabled) :
			_('Mesh operation did not complete. Check the rollback result.'))]),job.phase==='complete' ? 'info' : 'error');
	}
	if(job && previewRequested===job.id && ['ready','complete','failed','partial','cancelled','expired'].indexOf(job.phase)>=0) {
		previewRequested=null;
		if(job.phase==='ready' || job.root.has_plan || job.nodes.some(function(node){return node.has_plan;}))
			window.setTimeout(function(){reviewStop(data,job,refresh,writable);},0);
		else if(job.failure)ui.addNotification(null,widgets.failure(job.failure),'error');
	}
	if(!job || job.phase==='complete' && !job.node_id && data.mesh_enabled!==job.enabled)return null;
	var members=data.cluster.members || [],actions=[];
	if(job.phase==='ready')actions.push(button(_('Review restore preview'),function(){reviewStop(data,job,refresh,writable);},!writable));
	if(!terminal(job.phase))
		actions.push(button(_('Cancel'),function(){return call('mesh_stop_cancel',job.id).then(refresh).catch(notify);},!writable));
	var message=job.phase==='complete' ? resultMessage(job.enabled) :
		job.phase==='awaiting_confirm' ? _('Configuration restored. Confirm to finish disabling Mesh.') :
		job.phase==='ready' ? _('Restore preview is ready. Review and approve it before applying.') : label(job.phase);
	var target=members.find(function(node){return node.id===job.node_id;});
	var rows=job.nodes.map(function(node){
			var m=members.find(function(n){return n.id===node.id;});
			return [m && m.name || node.id,label(node.status),node.plan && node.plan.errors && node.plan.errors.length ?
				planBody(node.plan)[0] : widgets.failure(node.error,'mesh-stop:'+job.id+':'+node.id) || '-'];
	});
	if(!job.node_id)rows.unshift([_('This device'),label(job.root.status),widgets.failure(job.root.error,'mesh-stop:'+job.id+':root') || '-']);
	var body=[E('p',{'role':'status','aria-live':'polite'},[
		widgets.status((target ? target.name+': ' : '')+message,job.phase==='complete' ? 'good' :
			job.phase==='failed' || job.phase==='partial' ? 'error' : 'warning')
	])];
	if(job.failure)body.push(widgets.failure(job.failure,'mesh-stop:'+job.id));
	body.push(widgets.details(_('Node results'),[widgets.table([_('Node'),_('Status'),_('Details')],rows)]));
	var section=widgets.section(_('Latest Mesh operation'),body,actions);
	section.classList.add('mm-mesh-operation');section.dataset.mmPhase=job.phase;
	return section;
}
function history(data,refresh,writable) {
	var members=data.cluster.members || [];
	if(!data.history_counts.lifecycle || data.cluster.identity.role!=='root')return null;
	return historyPages.section('mesh-history', 'lifecycle',_('Mesh operation records'),[
		_('Time'),_('Status'),_('Node'),_('Details')
	],function(job){
		var nodes=(job.nodes || []).map(function(node){
			var member=members.find(function(m){return m.id===node.id;});
			return (member && member.name || node.id.slice(0,8))+': '+label(node.status);
		});
		var reason=(job.nodes || []).find(function(node){return node.error;});
		return [new Date(job.timestamp*1000).toLocaleString(),
			widgets.status(label(job.phase),job.phase==='complete' ? 'good' : job.phase==='failed' ? 'error' : 'warning'),
			nodes.join(', ') || _('This device'),widgets.failure(reason ? reason.error+': '+(job.failure || '') : job.failure,'mesh-history:'+job.id) || '-'];
	},_('No Mesh operation records'),{writable:writable,refresh:refresh});
}
return baseclass.extend({localAction:localAction,nodeAction:nodeAction,stopStatus:stopStatus,history:history,state:state});
