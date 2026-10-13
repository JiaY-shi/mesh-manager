// SPDX-License-Identifier: GPL-2.0-only
'use strict';
'require baseclass';
'require rpc';
'require mesh_manager.widgets as widgets';
'require mesh_manager.history as historyPages';

var calls={};
['clients','history'].forEach(function(method){
	calls[method]=rpc.declare({object:'mesh-manager.roaming',method:method,
		params:['node_id','cursor','limit','fields','if_revision'],reject:true});
});
var root,select,body,selected='',names={};
function render(data) {
	var cluster=data.cluster || {},identity=cluster.identity || {},nodes=[];
	if(data.mesh_enabled && identity.id) {
		nodes.push({id:identity.id,name:identity.overrides && identity.overrides.name || identity.name || _('Local node')});
		if(identity.role==='root')(cluster.members || []).forEach(function(node){
			if(node.authorized && !node.mesh_paused)nodes.push(node);
		});
	}
	names={};nodes.forEach(function(node){names[node.id]=node.name || node.id;});
	if(selected && !names[selected])selected='';
	if(!root) {
		select=E('select',{'aria-label':_('Filter by node'),change:function(){selected=select.value;draw();}});
		body=E('div');
		root=E('div',{'class':'mm-clients'},[E('div',{'class':'mm-actions'},[
			E('label',{},[_('Node'), ' ',select])]),body]);
	}
	select.replaceChildren(E('option',{value:''},[_('All managed nodes')]));
	nodes.forEach(function(node){select.appendChild(E('option',{value:node.id},[names[node.id]]));});
	select.value=selected;
	select.parentNode.parentNode.hidden=nodes.length<2;
	function draw() {
		var node=selected;
		function table(group,headers,row,empty) {
			var notice=E('p',{'class':'mm-empty-state','role':'status','data-mm-client-freshness':group});
			var pager=historyPages.table('terminal-'+group+'-'+(node || 'all'),group,headers,row,empty,{
				maximum:group==='clients'?65*128:128,
				fetch:function(_group,cursor,limit,fields,revision){return calls[group](node,cursor,limit,fields,revision);},
				labels:{loading:_('Loading client observations…'),unavailable:_('Client observations unavailable'),
					expired:_('Client list changed or expired. Reload from the first page.'),
					failed:_('Client update failed. Displayed observations may be outdated.'),reload:_('Reload observations')},
				changed:function(page,pending,error){
					if(!page || group==='history'){notice.textContent='';return;}
					var sources=(page.nodes || []).filter(function(source){return !node || source.id===node;}),
						missing=sources.filter(function(source){return !source.available;});
					notice.textContent=error ? '' : missing.length ?
						_('No current observation from: %s').format(missing.map(function(source){return names[source.id] || source.name;}).join(', ')) :
						sources.length ? _('Latest complete samples, at most %s seconds old.').format(Math.ceil(Math.max.apply(null,sources.map(function(source){return source.age_ms || 0;}))/1000)) : _('Mesh is not enabled on an observation source.');
				}
			});
			return [notice,pager];
		}
		body.replaceChildren(
			widgets.section(_('Associated clients'),table('clients',[_('Client address'),_('Node'),_('Interface'),_('Signal'),_('Status')],function(client){
				return [client.address,names[client.node_id] || client.node_id,client.interface,
					client.signal==null?_('Unknown'):client.signal+' dBm',client.authorized?_('Authorized'):_('Not authorized')];
			},_('No associated clients reported'))),
			widgets.section(_('Client observations'),[E('p',{'class':'mm-empty-state'},[
				_('Observed movement between AP reports; handover is not independently verified.')])].concat(
				table('history',[_('Time'),_('Client address'),_('Status'),_('Node')],function(event){
					var place=event.kind==='node_change'?(names[event.from] || event.from)+' → '+(names[event.to] || event.to):names[event.to || event.from] || event.to || event.from;
					return [new Date(event.at*1000).toLocaleString(),event.client,event.kind==='node_change'?_('Observed AP change'):
						event.kind==='associated'?_('Associated'):_('Disconnected'),place];
				},_('No client observations yet')))));
	}
	draw();return root;
}
return baseclass.extend({render:render});
