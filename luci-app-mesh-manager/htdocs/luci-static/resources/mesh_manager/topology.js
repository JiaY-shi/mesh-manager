// SPDX-License-Identifier: GPL-2.0-only
'use strict';
'require baseclass';
'require rpc';
'require ui';
'require mesh_manager.widgets as widgets';
'require mesh_manager.history as history';

var fields=['id','name','role','gateway','local','mesh_enabled','online','management_address','address_source','backhaul','stale'];
var nodes=rpc.declare({object:'mesh-manager.topology',method:'nodes',params:['cursor','limit','fields','if_revision'],reject:true});
var detail=rpc.declare({object:'mesh-manager.topology',method:'detail',params:['node_id','fields','if_revision'],reject:true});
function role(node) {
	return node.role==='root' ? node.gateway==='bridge' ? _('Root bridge') : node.gateway==='router' ? _('Root router') : _('Controller') :
		node.role==='ap' ? _('AP node') : _('Not enrolled');
}
function status(node) {
	return widgets.status(node.mesh_enabled===false ? _('Disabled') : node.online===true ? _('Online') :
		node.online===false ? _('Offline') : _('Unavailable'),node.mesh_enabled===false ? 'neutral' :
		node.online===true ? 'good' : node.online===false ? 'warning' : 'neutral');
}
function address(node) {
	if(!node.management_address)return _('Unavailable');
	var source=node.address_source==='last_reported' ? _('Last reported') : node.address_source==='paired' ? _('Paired address') : '';
	return E('span',{'class':'mm-management-address'},[node.management_address,source ? ' ' : '',
		source ? E('small',{'class':'mm-muted'},[source]) : E('span')]);
}
function path(value) {
	return value==='wired' ? _('Wired') : value==='wireless' ? _('Wireless') : value==='none' ? _('No active path') : _('Unavailable');
}
function inspect(node) {
	var body=E('div',{'class':'mm-topology-detail'},[E('p',{'class':'mm-muted'},[_('Loading node details…')])]);
	widgets.modal(_('Node details'),[body,E('div',{'class':'mm-actions'},[E('button',{
		'class':'cbi-button cbi-button-neutral',type:'button',click:function(){ui.hideModal();}},[_('Close')])])]);
	return detail(node.id,[], '').then(function(reply) {
		if(!body.isConnected)return;
		if(!reply || !reply.ok || !reply.data || reply.data.node_id!==node.id || !reply.data.item)
			throw new Error('Node details unavailable');
		var item=reply.data.item;
		body.replaceChildren(widgets.facts([[_('Node'),item.name],[_('Role'),role(item)],
			[_('Status'),status(item)],[_('Management address'),address(item)],
			[_('Backhaul'),item.mesh_enabled===false ? '-' : path(item.backhaul)]]),
			widgets.details(_('Technical details'),[widgets.facts([[_('Model'),item.model || _('Unknown')],
				[_('Device identity'),item.id],[_('Mesh intent version'),item.cluster_version == null ? '-' : item.cluster_version],
				[_('Local transaction version'),item.local_version == null ? '-' : item.local_version],
				[_('Managed differences'),item.drift_count == null ? _('Unknown') : item.drift_count]])]),
			reply.data.stale ? E('p',{'class':'mm-muted'},[_('Some node information is unavailable or last reported.')]) : E('span'));
	}).catch(function() {
		if(body.isConnected)body.replaceChildren(E('p',{'class':'mm-error'},[_('Node details are unavailable. Reload the topology.')]));
	});
}
function table() {
	return history.table('topology-nodes','nodes',[_('Node'),_('Role'),_('Management address'),_('Backhaul'),_('Status')],function(node) {
		var name=E('a',{href:'#','data-mm-node':node.id,click:function(ev){ev.preventDefault();return inspect(node);}},[node.name || (node.role==='root' ? _('Controller') : node.id)]);
		return [E('span',{'class':node.role==='root' ? 'mm-topology-root' : 'mm-topology-child'},[name]),role(node),address(node),
			node.mesh_enabled===false || node.role==='root' ? '-' : path(node.backhaul),status(node)];
	},_('No enrolled nodes'),{
		maximum:65,fetch:function(group,cursor,limit,selection,revision){return nodes(cursor,limit,fields,revision);},
		labels:{loading:_('Loading topology…'),unavailable:_('Topology is unavailable'),
			expired:_('Topology changed or expired. Reload from the first page.'),
			failed:_('Topology update failed. Displayed nodes may be outdated.'),reload:_('Reload topology')},
		changed:function(){document.querySelectorAll('[data-mm-pager="topology-nodes"] table').forEach(function(node){node.classList.add('mm-topology');});}
	});
}
return baseclass.extend({table:table});
