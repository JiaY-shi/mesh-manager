'use strict';
'require baseclass';
'require mesh_manager.widgets as widgets';

function form(current, controls) {
	var field=controls.field, input=controls.input, checkbox=controls.checkbox, select=controls.select;
	var entries=['guest'].map(function(id) {
		var old=(current.networks || []).filter(function(n) { return n.id===id; })[0] || {},
			enabled=checkbox(old.enabled===true),ssid=input(old.ssid || (current.wifi && current.wifi.ssid || 'Mesh')+'-Guest'),
			key=input('','password'), encryption=select([['psk2','WPA2-PSK'],['sae-mixed','WPA2/WPA3']],old.encryption || 'psk2'),
			vlan=input(String(old.vlan || 'auto')),subnet=input(old.subnet || 'auto'),isolate=checkbox(old.id ? old.isolate!==false : true),internet=checkbox(old.internet!==false),
			lanAccess=checkbox(old.lan_access===true),
			access=input((old.access || []).map(function(rule) { return rule.protocol.toUpperCase()+':'+rule.ports.join(','); }).join(';'));
		ssid.maxLength=32;key.minLength=8;key.maxLength=63;key.placeholder=_('Leave empty to keep current password');
		vlan.pattern='auto|[0-9]{1,4}';vlan.maxLength=4;subnet.maxLength=20;
		access.maxLength=1024;access.pattern='(?:[Tt][Cc][Pp]|[Uu][Dd][Pp]):[0-9,]+(?:;(?:[Tt][Cc][Pp]|[Uu][Dd][Pp]):[0-9,]+)*';
		function visibility() {
			[ssid,key,encryption,vlan,subnet,isolate,internet,lanAccess,access].forEach(function(c) { c.disabled=!enabled.checked; });
			ssid.required=enabled.checked;key.required=enabled.checked && !old.id;
		}
		enabled.addEventListener('change',visibility);visibility();
		return { element:widgets.details(_('Guest network'),[E('div',{'class':'mm-form'},[
			field(_('Enable network'),enabled),field(_('SSID'),ssid),field(_('New passphrase'),key,_('Use an independent password for this network. Leave empty to keep its existing password.')),
			field(_('Encryption'),encryption),field(_('VLAN ID'),vlan,_('Use auto to allocate a free VLAN. The control VLAN is reserved.')),
			field(_('Business subnet'),subnet,_('Use auto or a private /24 subnet with gateway address .1. DHCP runs on the routing gateway.')),
			field(_('Client isolation'),isolate,_('Isolate wireless clients on the same AP. Guest access to LAN is controlled separately.')),field(_('Internet access'),internet),
			field(_('Allow mutual access with LAN'),lanAccess,_('Allow traffic in both directions between this network and the main LAN. Guest client isolation is configured separately.')),
			field(_('LAN access exceptions'),access,_('Optional LAN-to-network service ports, for example TCP:80,443;UDP:123. Used when mutual LAN access is disabled.'))
		])]), value:function() {
			return {id:id,enabled:enabled.checked,ssid:ssid.value,key:key.value || null,encryption:encryption.value,
				vlan:vlan.value==='auto' ? 'auto' : Number(vlan.value),subnet:subnet.value,isolate:isolate.checked,internet:internet.checked,lan_access:lanAccess.checked,
				access:access.value ? access.value.split(';').map(function(rule) { var pieces=rule.split(':');return {
					from:'lan',protocol:pieces[0].toLowerCase(),ports:(pieces[1] || '').split(',').map(Number)}; }) : []};
		} };
	});
	return { element:E('div',{},entries.map(function(n) { return n.element; })),value:function() {
		return {networks:entries.map(function(n) { return n.value(); })};
	} };
}
return baseclass.extend({ form:form });
