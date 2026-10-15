// SPDX-License-Identifier: GPL-2.0-only
'use strict';
'require baseclass';
'require rpc';
'require ui';
'require mesh_manager.widgets as widgets';
'require mesh_manager.slow_rpc as slow_rpc';

var status=rpc.declare({object:'mesh-manager',method:'migration_status',reject:true});
var cancel=rpc.declare({object:'mesh-manager',method:'migration_cancel',params:['request_id'],reject:true});
var resume=rpc.declare({object:'mesh-manager',method:'migration_resume',params:['request_id'],reject:true});
function unwrap(r) {
	if(!r || r.ok!==true)throw new Error(r && r.error ? r.error.message : _('Backend unavailable'));
	return r.data;
}
function pending(c) { return !!(c && c.migration && ['complete','cancelled','expired'].indexOf(c.migration.phase)<0); }
function label(phase) {
	return ({preflight:_('Checking all devices'),preparing:_('Preparing'),ready:_('Ready for approval'),
		applying:_('Applying'),awaiting_confirm:_('Checking network health'),committed:_('Configuration confirmed'),
		transferring:_('Transferring controller authority'),transferred:_('Authority received'),promoting:_('Activating new controller'),
		handover:_('Retiring previous controller authority'),switching:_('Connecting to new controller'),switched:_('Connected to new controller'),
		finishing:_('Completing migration'),complete:_('Migration complete'),cancelling:_('Cancelling'),cancelled:_('Cancelled'),
		failed:_('Migration needs attention'),error:_('Migration needs attention'),expired:_('Expired')})[phase] || _('Waiting');
}
function button(text, action, disabled) {
	function unavailable(){return typeof disabled==='function' ? disabled() : !!disabled;}
	var b=E('button',{'class':'cbi-button cbi-button-neutral','type':'button',disabled:unavailable()},[text]);
	b.addEventListener('click',function() {
		b.disabled=true;
		return Promise.resolve().then(action).catch(function(error) {
			ui.addNotification(null,E('p',{},[error.message]),'error');
		}).finally(function(){b.disabled=unavailable();});
	});return b;
}
function nodeName(c,id) {
	var identity=c.identity || {},n=(c.members || []).find(function(n){return n.id===id;});
	if(n && n.name)return n.name;
	if(id===identity.id)return (identity.overrides || {}).name || identity.name || _('This device');
	if(id===identity.controller_id)return _('Current controller');
	if(id===(identity.data_gateway || {}).id)return _('Data gateway');
	return _('AP node');
}
function changes(plan) {
	var table=E('table',{'class':'table'},[E('tr',{'class':'tr'},[_('Setting'),_('Before'),_('After')].map(function(h){return E('th',{'class':'th'},[h]);}))]);
	(plan && plan.ops || []).filter(function(o){return o.changed!==false;}).forEach(function(o) {
		table.appendChild(E('tr',{'class':'tr'},[o.config+'.'+o.section+(o.option ? '.'+o.option : ''),o.before,o.after].map(function(v) {
			return E('td',{'class':'td'},[typeof v==='object' ? JSON.stringify(v) : String(v==null ? '-' : v)]);
		})));
	});return table;
}
function review(c,refresh,writable) {
	return status().then(unwrap).then(function(m) {
		if(!m)throw new Error(_('Migration preview is unavailable'));
		var body=[widgets.facts([[_('Current controller'),nodeName(c,m.source)],[_('New controller'),nodeName(c,m.target)],
			[_('Data gateway'),m.anchor && m.anchor.address]]),E('p',{},[
			_('The data gateway, Internet connection and device identities are preserved. Existing enrollment invitations are invalidated. Keep every device connected by Ethernet until migration completes.')])];
		[{id:m.source,plan:m.root && m.root.plan}].concat(m.nodes || []).forEach(function(n) {
			body.push(E('h4',{},[nodeName(c,n.id)]),changes(n.plan));
			(n.plan && n.plan.warnings || []).forEach(function(w){body.push(E('p',{'class':'mm-muted'},[w]));});
		});
		var approve=E('input',{type:'checkbox'}),apply=button(_('Approve migration'),function() {
			if(!approve.checked)return;
			return slow_rpc.action('migration_apply',{request_id:m.id,approval:m,takeover:true}).then(unwrap).then(function() {
				ui.hideModal();return refresh(true);
			});
		},function(){return !writable || m.phase!=='ready' || !approve.checked;});
		apply.disabled=true;
		approve.addEventListener('change',function(){apply.disabled=!writable || m.phase!=='ready' || !approve.checked;});
		body.push(E('label',{'class':'mm-approval'},[approve,' ',_('I approve moving controller authority to the displayed device')]),
			E('div',{'class':'mm-actions'},[button(_('Close'),function(){ui.hideModal();}),apply]));
		widgets.modal(_('Review controller migration'),body);
	});
}
function section(data,c,refresh,writable) {
	var m=c.migration,id=c.identity || {},body=[];
	if(id.role!=='root' && !m)return widgets.section(_('Controller migration'),[
		E('p',{'class':'mm-muted'},[_('Controller migration is managed by the current controller.')])]);
	if(m) {
		body.push(widgets.status(label(m.phase),m.phase==='complete' ? 'good' : m.failure ? 'error' : 'neutral'),
			widgets.facts([[_('New controller'),E('span',{title:m.target},[nodeName(c,m.target)])],[_('Data gateway'),m.anchor && m.anchor.address]]));
		if(m.failure)body.push(widgets.failure(m.failure));
		if(m.nodes && m.nodes.length){
			var nodes=widgets.details(_('Nodes')+' ('+m.nodes.length+')',[E('ul',{'class':'mm-cluster-list'},m.nodes.map(function(n){
				return E('li',{'class':'mm-cluster-item'},[E('span',{'class':'mm-cluster-name',title:n.id},[nodeName(c,n.id)]),
					widgets.status(label(n.status),n.error ? 'error' : n.status==='complete' ? 'good' : 'neutral'),n.error ? widgets.failure(n.error) : E('span')]);
			}))]);
			nodes.setAttribute('data-mm-detail','migration-nodes:'+m.id);body.push(nodes);
		}
		if(m.target_address && /^\d+\.\d+\.\d+\.\d+$/.test(m.target_address) && ['switching','switched','finishing','complete'].indexOf(m.phase)>=0)
			body.push(E('a',{href:window.location.protocol+'//'+m.target_address+(window.location.port ? ':'+window.location.port : '')+L.url('admin','network','mesh-manager','advanced')},[_('Open new controller')]));
		if(id.role==='root' && pending(c))body.push(E('div',{'class':'mm-actions'},[
			button(_('Review migration'),function(){return review(c,refresh,writable);},!writable || m.phase!=='ready'),
			button(_('Cancel migration'),function(){return cancel(m.id).then(unwrap).then(refresh);},!writable || !m.cancel_allowed),
			button(_('Resume migration'),function(){return resume(m.id).then(unwrap).then(refresh);},!writable || !m.fenced)
		]));
	}
	if(id.role==='root' && !pending(c)) {
		var target=E('select',{'class':'cbi-input-select mm-migration-target',id:'mm-migration-target'});
		(c.members || []).filter(function(n){return n.authorized && n.online && !n.mesh_paused && n.report &&
			(n.report.backhaul && n.report.backhaul.active==='wired' || id.data_gateway && id.data_gateway.id===n.id && n.report.backhaul && n.report.backhaul.active==='gateway');
		}).forEach(function(n){target.appendChild(E('option',{value:n.id},[n.name || n.id]));});
		body.push(E('p',{'class':'mm-muted'},[_('Move controller management manually to a synchronized device. The data gateway stays on its current device.')]),
			E('div',{'class':'mm-form'},[E('div',{'class':'mm-field'},[
				E('label',{'class':'cbi-value-title',for:'mm-migration-target'},[_('New controller')]),
				E('div',{'class':'cbi-value-field'},[target])])]),
			E('div',{'class':'mm-actions'},[button(_('Preview controller migration'),function() {
				var bytes=new Uint8Array(16);window.crypto.getRandomValues(bytes);
				var request=Array.from(bytes).map(function(b){return b.toString(16).padStart(2,'0');}).join('');
				return slow_rpc.action('migration_preflight',{node_id:target.value,request_id:request}).then(unwrap).then(function(){return refresh(true);});
			},!writable || !target.options.length || !data.mesh_enabled || !!(data.drift || []).length)]));
	}
	var section=widgets.section(_('Controller migration'),body);section.classList.add('mm-migration');return section;
}
return baseclass.extend({pending:pending,section:section});
