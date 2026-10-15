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
	var old=current.wifi && current.wifi.planning || {},enabled=checkbox(old.enabled===true),
		six=select([['off',_('Disabled')],['prefer',_('Use when available')],['require',_('Require on every node')]],old.six_ghz || 'off'),
		channel=select([['auto',_('Automatic')],['keep',_('Keep current')]],old.channel || 'auto'),
		power=select([['auto',_('Automatic')],['keep',_('Keep current')]],old.power || 'auto'),ceiling=input(String(old.max_txpower_dbm || 20),'number'),country=input(old.country || ''),
		bands=['2g','5g','6g'].map(function(band) { return {band:band,control:checkbox((old.bands || ['2g','5g','6g']).indexOf(band)>=0)}; });
	ceiling.min=1;ceiling.max=30;ceiling.step=1;
	country.maxLength=2;country.pattern='[A-Z]{2}';country.placeholder='CN';
	return { element:E('div',{},entries.map(function(n) { return n.element; }).concat([
		widgets.details(_('Automatic radio planning'),[E('div',{'class':'mm-form'},[
			field(_('Enable planning'),enabled),field(_('Client bands'),E('div',{'class':'mm-radio-list'},bands.map(function(b) { return E('label',{},[b.control,' ',b.band==='2g' ? '2.4 GHz' : b.band==='5g' ? '5 GHz' : '6 GHz']); }))),
			field(_('6 GHz policy'),six,_('6 GHz requires WPA3. Nodes without 6 GHz use their other selected bands when available.')),
			field(_('Country code'),country,_('Use the actual country of operation. To change it, first apply with channels and power kept; then preview automatic planning after the driver refreshes.')),
			field(_('Client channels'),channel,_('Planning uses legal driver frequencies and passive load observations. A radio shared with wireless backhaul keeps the coordinated backhaul channel.')+' '+_('Native 5 GHz coexistence may exchange the primary and secondary channels within the approved block.')),
			field(_('Transmit power'),power),field(_('Power ceiling (dBm)'),ceiling,_('Choose the highest driver power candidate at or below the ceiling. If none is available, planning is refused. Actual driver power is checked before confirmation.'))
		])])
	])), value:function() {
		return { networks:entries.map(function(n) { return n.value(); }),planning:{enabled:enabled.checked,
			bands:bands.filter(function(b) { return b.control.checked; }).map(function(b) { return b.band; }),six_ghz:six.value,
			channel:channel.value,power:power.value,max_txpower_dbm:Number(ceiling.value),country:country.value || null} };
	} };
}
return baseclass.extend({ form:form });
