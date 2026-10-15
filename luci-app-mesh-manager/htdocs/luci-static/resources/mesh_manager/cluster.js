// SPDX-License-Identifier: GPL-2.0-only
'use strict';
'require mesh_manager.network_extensions as extensions';
'require mesh_manager.history as history';
'require mesh_manager.slow_rpc as slow_rpc';
'require baseclass';
'require rpc';
'require ui';
'require dom';
'require mesh_manager.widgets as widgets';
'require mesh_manager.lifecycle as lifecycle';
'require mesh_manager.topology as topology';

var rpcMethods = {};
[
	['controller_init',['name','address','gateway','local','takeover']], ['discover',['mode','timeout']],
	['onboard_status',[]],
	['onboard_stop',[]],
	['node_revoke',['node_id']], ['node_rename_preview',['node_id','name']],
	['node_rename',['request_id','approval','takeover']],
	['local_overrides_stage',['local','request_id','takeover','approval']], ['apply',['transaction_id']],
	['cluster_preflight',['intent','request_id','maintenance']], ['cluster_apply',['transaction_id','approval','takeover']],
	['cluster_rollback',['transaction_id']],
	['status_detail',['kind','node_id','id']],
	['node_repair',['node_id','request_id']], ['node_repair_apply',['node_id','request_id','approval','takeover']],
	['node_repair_rollback',['node_id','request_id']]
	, ['setup_create',['name','address','gateway','local','intent','request_id','takeover']],
	['enrollment_start',['name','local','ssid','password','bssid','device','candidate','takeover']], ['enrollment_stop',[]]
].forEach(function(spec) { rpcMethods[spec[0]] = rpc.declare({object:'mesh-manager',method:spec[0],params:spec[1],reject:true}); });
rpcMethods.local_overrides_stage=function(local,request_id,takeover,approval) {
	return slow_rpc.action('local_overrides_stage',{local:local,request_id:request_id,takeover:takeover,approval:approval});
};
function call(method) {
	return rpcMethods[method].apply(null,Array.prototype.slice.call(arguments,1)).then(function(r) {
		if (!r || r.ok !== true) {
			var error = new Error(r && r.error ? r.error.message : _('Backend unavailable'));
			error.code = r && r.error && r.error.code;
			if(method==='local_overrides_stage' && ['request_timeout','backend_unavailable'].indexOf(error.code)>=0)error.code='outcome_unknown';
			throw error;
		}
		return r.data;
	});
}
function retryBusy(method, args, waiting, attempt, active) {
	attempt = attempt || 0;
	function cancelled() { var error=new Error('Cancelled');error.code='job_cancelled';return error; }
	if(active && !active())return Promise.reject(cancelled());
	// Only idempotent preflight, name transactions and read-only requests use this helper.
	// The caller keeps one request ID and one candidate for the whole attempt.
	return call.apply(null, [method].concat(args)).then(function(result) {
		if(active && !active())throw cancelled();
		return result;
	}).catch(function(error) {
		if(active && !active())throw cancelled();
		if (error.code !== 'busy' || attempt >= 4) throw error;
		if (waiting) waiting();
		return new Promise(function(resolve) { window.setTimeout(resolve, 250 * (attempt + 1)); }).then(function() {
			return retryBusy(method, args, waiting, attempt + 1, active);
		});
	});
}
function text(v) { return v == null ? '-' : typeof v === 'object' ? JSON.stringify(v) : String(v); }
function notify(e) { ui.addNotification(null,E('p',{},[widgets.configurationError(e)]),'error'); }
function button(label,fn,disabled) { return E('button',{type:'button','class':'cbi-button cbi-button-neutral',disabled:disabled || null,click:ui.createHandlerFn(null,fn)},[label]); }
var field = widgets.field;
function input(value,type) { return E('input',{type:type || 'text',value:value || '',autocomplete:type === 'password' ? 'new-password' : 'off'}); }
function checkbox(value) { return E('input',{type:'checkbox',checked:value ? '' : null}); }
function select(items,value) { return E('select',{},items.map(function(item) { return E('option',{value:item[0],selected:item[0] === value ? '' : null},[item[1]]); })); }
var table = widgets.table;
function requestId() { var b=new Uint8Array(16); window.crypto.getRandomValues(b); return Array.from(b).map(function(n) { return n.toString(16).padStart(2,'0'); }).join(''); }
function stateLabel(state) {
	var labels={unbound:_('Not enrolled'),root:_('Controller'),ap:_('AP node'),pending:_('Registering node identity'),approved:_('Approved'),rejected:_('Rejected'),preflight:_('Preflighting'),ready:_('Ready'),queued:_('Queued'),preparing:_('Preparing repair preview'),reserved:_('Local repair reserved'),applying:_('Applying'),awaiting_confirm:_('Awaiting confirmation'),confirming:_('Confirming'),committed:_('Committed'),complete:_('Complete'),partial:_('Partially completed'),failed:_('Failed'),rolling_back:_('Rolling back'),rolled_back:_('Rolled back'),rollback_conflict:_('Rollback conflict'),expired:_('Expired')};
	return state==null ? '-' : labels[state] || state;
}
function enrollmentLabel(state) {
	return ({searching_wired:_('Searching on wired LAN'),searching_wireless:_('Scanning nearby Wi-Fi'),
		waiting_retry:_('Retrying in 30 seconds'),waiting_authorization:_('Waiting for the controller to become available'),
		select_controller:_('Multiple controllers found; select a network'),pending:_('Registering node identity'),
		rejected:_('Rejected'),configuring:_('Applying controller configuration'),
		configuration_retry:_('Configuration rolled back; retrying after 30 seconds'),
		configuration_reconnect:_('Configuration rolled back; waiting for the controller connection before retrying'),
		configuration_blocked:_('Configuration preflight failed; waiting for the issue to be resolved'),
		recovery_conflict:_('Recovery conflict; inspect node changes before retrying'),
		joined:_('Joined'),stopped:_('Stopped')})[state] || _('Not started');
}
function pathLabel(path) {
	return path === 'wired' ? _('Wired') : path === 'wireless' ? _('Wireless') :
		path === 'none' ? _('No active path') : _('Unknown');
}
function backhaulModeLabel(mode) {
	return mode === 'wired' ? _('Wired') : mode === 'wireless' ? _('802.11s wireless') :
		mode === 'auto' ? _('Wired preferred, wireless standby') : _('Unknown');
}
function localFields(data,identity) {
	var old=identity.overrides || {}, addresses=data.local.management && data.local.management.addresses || [];
	var root=identity.role==='root', router=root && identity.gateway!=='bridge';
	var protocol=select((root ? [] : [['dhcp',_('Upstream DHCP')]]).concat([['static',_('Static address')]]),root ? 'static' : old.management && old.management.protocol || 'dhcp');
	var address=input(root ? identity.address || addresses[0] && addresses[0].address || '' : old.management && old.management.address || addresses[0] && addresses[0].address || ''), mask=input(old.management && old.management.netmask || '255.255.255.0');
	var gateway=input(old.gateway || ''), uplink=input(old.uplink || data.local.wan_device || 'wan');
	var radios=(data.capabilities.radios || []).map(function(r) { return {name:r.name,box:checkbox(!old.radios || old.radios.indexOf(r.name)>=0),band:r.band}; });
	var mesh=select([['',_('None')]].concat(radios.map(function(r) { return [r.name,r.name+(r.band ? ' ('+r.band+')' : '')]; })),old.mesh_radio || (radios.filter(function(r) { return r.band === '5g'; })[0] || {}).name || '');
	var legacy=checkbox(old.disable_legacy_mesh), name=input(old.name || identity.name || data.local.board && data.local.board.model || 'OpenWrt');
	address.readOnly=root;
	var addressField=field(_('IPv4 address'),address,root ? _('Coordinated controller address migration is not implemented; preserve the existing static LAN address') : _('A local override, not synchronized to other nodes. Choose an unused address outside the upstream DHCP pool.'));
	var maskField=field(_('Netmask'),mask,_('Must match the management subnet. An incorrect address or mask can disconnect this device.'));
	var gatewayField=field(_('Bridge gateway override'),gateway,_('Only for static bridge/AP management. Leave empty to preserve existing local gateway and DNS settings.'));
	function visibility() {
		protocol.disabled=root;
		address.disabled=mask.disabled=protocol.value!=='static';
		addressField.hidden=maskField.hidden=protocol.value!=='static';
		gatewayField.hidden=router || protocol.value!=='static';
	}
	protocol.addEventListener('change',visibility);visibility();
	return {
		fields:[field(_('Node name'),name,_('A display name for this device; it does not change its cryptographic identity.')),
			field(_('Local radios'),E('div',{'class':'mm-radio-list'},radios.map(function(r) { return E('label',{},[r.box,' ',r.name+(r.band ? ' ('+r.band+')' : '')]); })),_('Map the unified client Wi-Fi to radios actually present on this device. Radio names are not copied from the controller.')),
			field(_('Wireless backhaul radio'),mesh,_('Used only for 802.11s backhaul. Client roaming and node backhaul are separate features.'))]
			.concat(identity.role==='root' ? [] : [field(_('AP uplink port'),uplink,_('Physical port connected to the upstream LAN. Taking over a WAN port disables its local routing and bridges it into the AP LAN.'))])
			.concat([field(_('Management protocol'),protocol,root ? _('Coordinated controller address migration is not implemented; preserve the existing static LAN address') : _('AP nodes obtain management addresses from the existing gateway by default.')),
			addressField,maskField,gatewayField,
			field(_('Approve legacy mesh takeover'),legacy,_('Explicitly disable an existing mesh interface before creating managed backhaul to avoid competing paths and loops. Original settings remain available for restoration.'))]),
		value:function() {
			var management={interface:'lan',protocol:protocol.value};
			if(protocol.value==='static') { management.address=address.value;management.netmask=mask.value; }
			return Object.assign({},old,{name:name.value,radios:radios.filter(function(r) { return r.box.checked; }).map(function(r) { return r.name; }),mesh_radio:mesh.value || null,uplink:identity.role==='root' ? null : uplink.value,
			management:management,gateway:gateway.value || null,disable_legacy_mesh:legacy.checked}); },
		gatewayMode:function(mode) {
			router=root && mode==='router';
			protocol.value=root ? 'static' : old.management && old.management.protocol || 'dhcp';
			visibility();
		}
	};
}
function approvalModal(title,body,perform,writable,consent,control) {
	function active() { return !control || control.active(); }
	var approve=checkbox(false), sending=false, apply=button(_('Approve'),function() {
		if (sending || !approve.checked || !writable || !active()) return;
		sending=true; apply.disabled=true;
		return perform().then(function() { if(active())ui.hideModal(); }).catch(function(error) {
			if(!active() || control && error.code==='job_cancelled')return;
			sending=false; approve.checked=false; apply.disabled=true;
			if (error.code==='preview_changed') error.message=consent ? _('The node changed. Close this dialog and review its name again.') : _('Repair preview changed; close this dialog and review again.');
			notify(error);
		});
	},true);
	approve.addEventListener('change',function() { apply.disabled=sending || !approve.checked || !writable || !active(); });
	apply.classList.add('cbi-button-apply');
	return widgets.modal(title,body.concat([E('label',{'class':'mm-approval'},[approve,' ',consent || _('I approve the displayed configuration takeover')]),E('div',{'class':'mm-actions mm-dialog-actions'},[button(_('Cancel'),function() {
		if(!active())return;if(control)control.cancel();ui.hideModal();
	}),apply])]));
}
function localSettingRows(values) {
	values=values || {};
	var labels={name:_('Node name'),radios:_('Local radios'),mesh_radio:_('Wireless backhaul radio'),uplink:_('AP uplink port'),management:_('Management protocol'),gateway:_('Bridge gateway override'),disable_legacy_mesh:_('Allow legacy Mesh takeover')};
	function settingValue(key,value) {
		if(value==null)return '-';
		if(key==='management')return value.protocol==='dhcp' ? _('Upstream DHCP') : _('Static address')+' · '+value.address+' / '+value.netmask;
		if(Array.isArray(value))return value.join(', ') || _('None');
		if(typeof value==='boolean')return value ? _('Enabled') : _('Disabled');
		return text(value);
	}
	return Object.keys(values.after || {}).filter(function(key) { return JSON.stringify(values.before && values.before[key] != null ? values.before[key] : null)!==JSON.stringify(values.after[key] ?? null); }).map(function(key) {
		return [labels[key] || key,settingValue(key,values.before && values.before[key]),settingValue(key,values.after[key])];
	});
}
function localSettingsPreview(local, data, refresh, writable) {
	var progress=E('p',{},[_('Preview queued')]), cancelled=false, id=requestId();
	var control={progress:function(state) { progress.textContent=state==='running' ? _('Preparing configuration preview') : _('Preview queued'); }};
	widgets.modal(_('Local settings'),[progress,E('div',{'class':'mm-actions'},[button(_('Cancel'),function() {
		cancelled=true;ui.hideModal();return control.cancel ? control.cancel().catch(notify) : Promise.resolve();
	})])]);
	return slow_rpc.preview(control,'local_overrides_preview',{local:local}).then(function(reply) {
		if(cancelled)return;
		if(!reply || !reply.ok) { var error=new Error(reply && reply.error && reply.error.message || _('Backend unavailable'));error.code=reply && reply.error && reply.error.code;throw error; }
		var plan=reply.data, rows=localSettingRows(plan.local_settings);
		approvalModal(_('Local settings'),[
			E('p',{},[_('Apply these settings to this device now. Confirm after health checks pass; otherwise the previous values are restored automatically.')]),
			table([_('Setting'),_('Before'),_('After')],rows,_('No changed fields')),
			E('ul',{},(plan.errors || []).map(function(error) { return E('li',{'class':'mm-error'},[widgets.configurationError(error)]); })),
			widgets.details(_('Configuration changes'),[table([_('Setting'),_('Before'),_('After')],plan.ops.filter(function(op) { return op.changed!==false; }).map(function(op) {
				return [op.config+'.'+op.section+(op.option ? '.'+op.option : ''),text(op.before),text(op.after)];
			}),_('No changed fields'))])
		],function() { return retryBusy('local_overrides_stage',[local,id,true,plan]).then(function(staged) {
			return retryBusy('apply',[staged.id]);
		}).then(function() { return refresh(true); }).catch(function(error) {
			if(error.code!=='outcome_unknown')throw error;
			error.message=_('Could not confirm the result. Check the latest local change before retrying.');
			return refresh(true).then(function() { notify(error); });
		}); },writable && widgets.recoveryReady(data) && !(plan.errors || []).length);
	}).catch(function(error) { if(cancelled || error.code==='job_cancelled')return;ui.hideModal();notify(error); });
}
function setup(data,c,refresh,writable) {
	var identity=c.identity || {}, controllerFields=localFields(data,Object.assign({},identity,{role:'root'})), joinFields=localFields(data,Object.assign({},identity,{role:'ap'}));
	var mode=select([['router',_('Root router')],['bridge',_('Root bridge')]],identity.gateway || 'router'), name=input(identity.name || 'Mesh'),address=input(identity.role==='root' && identity.address || data.local.management && data.local.management.addresses[0] && data.local.management.addresses[0].address || '');
	address.readOnly=true;
	var ssid=input(''), password=input('','password'), bootstrapSsid=input(''), bootstrapPassword=input('','password');
	ssid.maxLength=32; password.minLength=8; password.maxLength=63; ssid.required=password.required=true;
	var automaticState=E('span',{'class':'mm-scan-status','role':'status'}),autoStart,autoStop;

	mode.addEventListener('change',function() { controllerFields.gatewayMode(mode.value); });
	var discovery=E('div',{'class':'mm-discovery-list'}),discovered=false,scanId=0;
	var scanStatus=E('span',{'class':'mm-scan-status'});
	var wiredWindow=select([['5','5 s'],['10','10 s'],['20','20 s']],'10');
	var wirelessWindow=select([['5','5 s'],['10','10 s'],['20','20 s']],'10');
	var onboardState=E('div',{'class':'mm-onboard-state'});
	bootstrapSsid.maxLength=32;bootstrapPassword.minLength=8;bootstrapPassword.maxLength=63;
	function beginJoin(wifi,password,point,candidate) {
		var local=joinFields.value();
		return call('enrollment_start',local.name,local,wifi || '',password || '',point && point.bssid || '',point && point.device || '',candidate || {},true).then(refresh);
	}
	function join(candidate) {
		approvalModal(_('Join the selected Mesh network'),[
			E('p',{},[_('The controller accepts Mesh routers automatically. This device applies the network configuration after health checks pass.')])
		],function(){return beginJoin('', '', null, candidate);},writable);
	}
	function updateOnboardStatus() {
		return call('onboard_status').then(function(state) {
			if(!state.active)return dom.content(onboardState,E('span'));
			dom.content(onboardState,E('div',{'class':'mm-onboard-line'},[
				widgets.status(state.connected ? _('Temporary Wi-Fi connected') : _('Temporary Wi-Fi connecting'),'warning'),
				E('span',{},[state.ssid+' / '+state.remaining+' s']),
				button(_('Disconnect temporary Wi-Fi'),function() { return call('onboard_stop').then(updateOnboardStatus).catch(notify); },!writable)
			]));
		}).catch(notify);
	}
	function joinWireless(point,presetPassword) {
		var password=input(presetPassword || '','password');
		password.required=true;password.minLength=8;password.maxLength=63;
		approvalModal(_('Connect for Mesh enrollment'),[
			table([_('Property'),_('Value')],[[_('Wi-Fi access point'),point.ssid],[_('BSSID'),point.bssid]]),
			field(_('Wi-Fi password'),password,_('Connect to the controller Wi-Fi. Mesh routers are accepted automatically; ordinary Wi-Fi clients remain clients.'))
		],function() {
			if(!password.checkValidity()){password.reportValidity();return Promise.reject(new Error(_('Enter the bootstrap Wi-Fi name and password.')));}
			return beginJoin(point.ssid,password.value,point);
		},writable);
	}
	function renderWired(entries) {
		dom.content(discovery,entries.map(function(candidate) {
			return E('div',{'class':'mm-discovery-row'},[
				E('div',{},[E('strong',{},[candidate.name]),E('small',{},[candidate.address+' / '+candidate.interface])]),
				widgets.status(_('Unverified announcement'),'warning'),
				button(_('Join this network'),function() { join(candidate); },!writable)
			]);
		}));
	}
	function renderWireless(points, available, password) {
		dom.content(discovery,points.length ? points.map(function(point) {
			return E('div',{'class':'mm-discovery-row'},[
				E('div',{},[E('strong',{},[point.ssid]),E('small',{},[point.bssid+' / '+point.signal+' dBm'])]),
				widgets.status(_('Unverified Wi-Fi'),'warning'),
				button(_('Connect and request to join'),function() { joinWireless(point,password); },!writable)
			]);
		}) : E('p',{'class':'mm-empty'},[available ? _('No Wi-Fi access points found') :
			_('Wireless scan unavailable')]));
	}
	function refreshDiscovery() {
		var id=++scanId,wiredDeadline=Date.now()+Number(wiredWindow.value)*1000;
		dom.content(discovery,E('p',{'class':'mm-empty'},[_('Searching on wired LAN')]));
		function wireless() {
			var deadline=Date.now()+Number(wirelessWindow.value)*1000;
			function attempt() {
				if(id!==scanId)return;
				dom.content(scanStatus,_('Scanning nearby Wi-Fi'));
				return call('discover','wireless',Math.max(1,Math.ceil((deadline-Date.now())/1000))).then(function(result) {
					if(id!==scanId)return;
					var points=result.access_points || [];
					if(points.length || Date.now()>=deadline) {
						dom.content(scanStatus,result.available ? _('Wireless scan finished') :
							_('Wireless scan unavailable'));
						renderWireless(points,result.available);
					} else window.setTimeout(attempt,1000);
				}).catch(function(error) {
					if(id!==scanId)return;
					if(Date.now()<deadline)window.setTimeout(attempt,1000);
					else { dom.content(scanStatus,_('Wireless scan unavailable'));notify(error); }
				});
			}
			return attempt();
		}
		function wired() {
			if(id!==scanId)return;
			dom.content(scanStatus,_('Searching on wired LAN'));
			return call('discover','wired').then(function(result) {
				if(id!==scanId)return;
				var entries=(result.candidates || []).filter(function(candidate) { return !candidate.binding_conflict; });
				if(entries.length) { dom.content(scanStatus,_('Wired controller found'));renderWired(entries); }
				else if(Date.now()<wiredDeadline)window.setTimeout(wired,1000);
				else wireless();
			}).catch(function(error) {
				if(id!==scanId)return;
				if(Date.now()<wiredDeadline)window.setTimeout(wired,1000);
				else wireless();
			});
		}
		return wired();
	}
	var controllerPanel=E('div',{'class':'mm-enrollment-panel'},[
		E('div',{'class':'mm-form'},[
			field(_('Controller gateway role'),mode,_('Both Root modes manage AP nodes. Root router provides DHCP and NAT; Root bridge uses an existing upstream gateway and does not provide DHCP or NAT.')),
			field(_('SSID'),ssid), field(_('Passphrase'),password)
		]),
		widgets.details(_('Advanced settings'),[
			E('div',{'class':'mm-form'},[field(_('Network name'),name,_('A display name only. Each network has one controller identity; matching names do not authorize a device.')),
				field(_('Controller LAN address'),address,_('Coordinated controller address migration is not implemented; preserve the existing static LAN address'))]
				.concat(controllerFields.fields.filter(function(_item,index) { return index!==4; })))
		]),
		button(_('Create and enable Mesh'),function() {
			if(!ssid.checkValidity() || !password.checkValidity()){(!ssid.checkValidity() ? ssid : password).reportValidity();return;}
			var local=controllerFields.value();local.uplink=null;local.management.address=address.value;local.management.protocol='static';
			var intent={schema:2,name:name.value,wifi:{enabled:true,ssid:ssid.value,key:password.value,encryption:'psk2',
				roaming:{k:true,v:true,r:data.capabilities.ft!==false,steering:false,domain:requestId().slice(0,4)}},backhaul:{mode:'wired'},networks:[]};
			return call('setup_create',name.value,address.value,mode.value,local,intent,requestId(),true).then(function(job){
				return refresh().then(function(next){reviewCluster(next,next.cluster,job,refresh,writable);});
			}).catch(notify);
		},!writable)
	]);
	var joinPanel=E('div',{'class':'mm-enrollment-panel'},[
		E('p',{'class':'mm-muted'},[_('For wired joining, connect this router to the controller LAN. For wireless joining, enter the controller Wi-Fi name and password.')]),
		E('div',{'class':'mm-form'},[
			field(_('Bootstrap Wi-Fi name'),bootstrapSsid),field(_('Bootstrap Wi-Fi password'),bootstrapPassword)
		]),
		E('div',{'class':'mm-actions'},[
			(autoStart=button(_('Join Mesh'),function(){
				if(bootstrapSsid.value || bootstrapPassword.value) {
					if(!bootstrapSsid.value || !bootstrapPassword.value || !bootstrapPassword.checkValidity()) {
						notify(new Error(_('Enter the bootstrap Wi-Fi name and password.')));return;
					}
					return call('discover','wireless',Number(wirelessWindow.value)).then(function(scan){
						var points=(scan.access_points || []).filter(function(ap){return ap.ssid===bootstrapSsid.value;});
						if(!points.length)throw new Error(_('The bootstrap Wi-Fi network was not found. Check the SSID and radio, then scan again.'));
						if(points.length===1)return joinWireless(points[0],bootstrapPassword.value);
						renderWireless(points,true,bootstrapPassword.value);
					}).catch(notify);
				}
				return join(null);
			},!writable || !!identity.joining)),
			(autoStop=button(_('Stop joining'),function(){return call('enrollment_stop').then(refresh).catch(notify);},!writable || !(identity.enrollment && identity.enrollment.enabled))),automaticState
		]),
		widgets.section(_('Discover Mesh controllers'),[
			E('div',{'class':'mm-discovery-controls'},[button(_('Retry discovery'),refreshDiscovery),scanStatus]),discovery,onboardState
		]),
		widgets.details(_('Advanced settings'),[
			E('div',{'class':'mm-form'},joinFields.fields.concat([field(_('Wired timeout'),wiredWindow),field(_('Wireless timeout'),wirelessWindow)]))
		])
	]);
	var controllerTab=E('button',{type:'button','class':'cbi-button mm-mode-button'},[_('Create controller')]);
	var joinTab=E('button',{type:'button','class':'cbi-button mm-mode-button'},[_('Request to join')]);
	function selectMode(join) {
		controllerPanel.hidden=join;
		joinPanel.hidden=!join;
		controllerTab.classList.toggle('mm-mode-active',!join);
		joinTab.classList.toggle('mm-mode-active',join);
		controllerTab.setAttribute('aria-pressed',String(!join));
		joinTab.setAttribute('aria-pressed',String(join));
		if(join && !discovered) { discovered=true;updateOnboardStatus(); }
		if(!join)scanId++;
	}
	controllerTab.addEventListener('click',function() { selectMode(false); });
	joinTab.addEventListener('click',function() { selectMode(true); });
	selectMode(identity.role!=='root');
	var section=widgets.section(identity.role==='root' ? _('Setup incomplete') : _('Mesh enrollment'),[
		E('div',{'class':'mm-mode','role':'group'},[controllerTab,joinTab]),controllerPanel,joinPanel
	]);
	section.mmUpdate=function(next){identity=next.cluster.identity;var e=identity.enrollment;
		dom.content(automaticState,e && e.enabled && e.runtime_error==='runtime_unavailable' ?
			widgets.status(_('Automatic discovery is unavailable; retrying.'),'warning') :
			e && ['waiting_retry','configuration_blocked'].indexOf(e.status)>=0 && e.error ? widgets.status(widgets.configurationError({code:e.error}),'warning') : enrollmentLabel(e && e.status));
		autoStart.textContent=_('Join Mesh');
		autoStart.disabled=!writable || !!(e && e.enabled) || !!identity.joining && ['requesting','pending'].indexOf(identity.joining.status)<0;
		autoStop.disabled=!writable || !(e && e.enabled) || next.cluster.identity.role!=='unbound';
	};
	section.mmUpdate(data);return section;
}
function unifiedForm(data,c,refresh,writable,page) {
	var current=c.intent || {}, w=current.wifi || {}, r=w.roaming || {}, b=current.backhaul || {};
	var networks=extensions.form(current,{field:field,input:input,checkbox:checkbox,select:select});
	var enabled=checkbox(w.enabled !== false),ssid=input(w.ssid || data.intent && data.intent.wifi.ssid || ''),key=input('','password'),enc=select([['psk2','WPA2-PSK'],['sae-mixed','WPA2/WPA3']],w.encryption || 'psk2');
	var k=checkbox(r.k !== false),v=checkbox(r.v !== false),ft=checkbox(r.r !== false),steer=checkbox(r.steering),domain=input(r.domain || '4f57');
	var customPolicy=checkbox(!!r.policy),policy=r.policy || {scan_rssi:-70,trigger_rssi:-75,signal_difference:8,interval_seconds:60};
	var thresholds={};
	Object.keys(policy).forEach(function(name) { thresholds[name]=input(String(policy[name]),'number'); });
	[['scan_rssi',-90,-40],['trigger_rssi',-90,-40],['signal_difference',3,30],['interval_seconds',30,600]].forEach(function(spec) {
		var control=thresholds[spec[0]];control.min=spec[1];control.max=spec[2];control.step=1;control.required=true;
		control.setAttribute('data-mm-policy',spec[0]);
	});
	var policyFields;
	var modes=[['wired',_('Wired')]];
	(data.capabilities.backhaul_modes || []).forEach(function(m) { if (m!=='wired') modes.push([m,m==='auto' ? _('Wired preferred, wireless standby') : m==='wireless' ? _('802.11s wireless') : 'batman-adv']); });
	if(b.mode && !modes.some(function(item) { return item[0]===b.mode; }))modes.push([b.mode,pathLabel(b.mode)]);
	var backhaul=select(modes,b.mode || 'wired'),meshid=input(b.mesh_id || 'mm-'+(c.identity.network_id || c.identity.id).slice(0,12)),meshkey=input('','password'),channel=input(String(b.channel || 36),'number');
	var width=select(['HT20','HT40','VHT20','VHT40','VHT80','HE20','HE40','HE80','HE160'].map(function(m) { return [m,m]; }),b.htmode || 'HE80');
	ssid.maxLength=32; key.maxLength=63; key.minLength=8;
	domain.maxLength=4; domain.pattern='[0-9a-fA-F]{4}';
	meshid.maxLength=32; meshkey.maxLength=63; meshkey.minLength=16; channel.min=1; channel.max=233;
	key.placeholder=_('Leave empty to keep current password');
	meshkey.placeholder=_('Keep existing or generate automatically');
	function candidate() {
		var path={mode:backhaul.value};
		if(b.control_vlan!=null)path.control_vlan=b.control_vlan;
		if(path.mode!=='wired')Object.assign(path,{mesh_id:meshid.value,
			key:meshkey.value || (current.backhaul && (b.mode===path.mode ||
				['auto','wireless'].indexOf(b.mode)>=0) ? null : (requestId()+requestId()).slice(0,48)),
			channel:Number(channel.value),htmode:width.value});
		var roaming={k:k.checked,v:v.checked,r:ft.checked,steering:steer.checked,domain:domain.value};
		if(customPolicy.checked) {
			roaming.policy={};Object.keys(thresholds).forEach(function(name) { roaming.policy[name]=Number(thresholds[name].value); });
		}
		var extra=networks.value(), planning=page==='wireless' ? extra.planning : w.planning;
		return {schema:2,name:current.name || c.identity.name || 'Mesh',wifi:{enabled:enabled.checked,ssid:ssid.value,encryption:enc.value,key:key.value || null,
			roaming:roaming,...(planning ? {planning:planning} : {})},backhaul:path,
			networks:page==='wireless' ? extra.networks : current.networks || []};
	}
	function needsMaintenance(path) {
		return !!current.backhaul && (path.key!=null || ['mode','mesh_id','channel','htmode','control_vlan'].some(function(name) { return path[name]!==b[name]; }));
	}
	function visibility() {
		meshid.disabled=meshkey.disabled=channel.disabled=width.disabled=backhaul.value==='wired';
		ssid.disabled=key.disabled=enc.disabled=!enabled.checked;
		ssid.required=enabled.checked; meshid.required=backhaul.value!=='wired';
		if(policyFields)policyFields.hidden=!customPolicy.checked;
		Object.keys(thresholds).forEach(function(name) { thresholds[name].disabled=!customPolicy.checked || !steer.checked; });
		thresholds.trigger_rssi.setCustomValidity(customPolicy.checked && Number(thresholds.trigger_rssi.value)>Number(thresholds.scan_rssi.value)-5
			? _('Set the transition threshold at least 5 dB below the scan threshold.') : '');
	}
	backhaul.addEventListener('change',visibility);enabled.addEventListener('change',visibility);visibility();
	customPolicy.addEventListener('change',visibility);steer.addEventListener('change',visibility);
	thresholds.scan_rssi.addEventListener('input',visibility);thresholds.trigger_rssi.addEventListener('input',visibility);
	policyFields=E('div',{'class':'mm-form mm-roaming-thresholds'},[
		field(_('Scan threshold (dBm)'),thresholds.scan_rssi,_('Request neighbor scans below this signal level. Range: -90 to -40 dBm; recommended: -70 dBm.')),
		field(_('Transition threshold (dBm)'),thresholds.trigger_rssi,_('Suggest a transition below this signal level. Keep it at least 5 dB below the scan threshold; recommended: -75 dBm.')),
		field(_('Candidate advantage (dB)'),thresholds.signal_difference,_('A candidate must have a stronger signal by this margin. Range: 3 to 30 dB; recommended: 8 dB.')),
		field(_('Suggestion interval (seconds)'),thresholds.interval_seconds,_('Minimum interval between transition suggestions. Range: 30 to 600 seconds; recommended: 60 seconds. Clients decide whether to roam.'))
	]);visibility();
	var basic=page==='wireless' ? [
		field(_('SSID'),ssid,_('Shared client Wi-Fi name across this Mesh network. This is not the backhaul Mesh ID.')),
		field(_('New passphrase'),key,_('Leave empty to keep the existing managed passphrase. A first configuration requires an 8 to 63 character passphrase. Secrets are never returned by status or preview.'))
	] : [field(_('Backhaul mode'),backhaul,_('Wired preferred uses one active data path and an authenticated standby path. Arbitrary multipath and multi-hop require the batman-adv backend.'))];
	var advanced=page==='wireless' ? [
		field(_('Manage wireless APs'),enabled,_('Configure managed client access points on the selected local radios. Existing APs require explicit takeover approval.')),
		field(_('Encryption'),enc),
		field(_('Roaming'),E('div',{'class':'mm-radio-list'},[[k,'802.11k'],[v,'802.11v'],[ft,'802.11r'],[steer,'usteer']].map(function(item) { return E('label',{},[item[0],' ',item[1]]); })),_('802.11k supplies neighbor information; 802.11v suggests transitions; 802.11r accelerates authentication. Clients decide when to roam. Steering requires usteer and must not run alongside DAWN.')),
		field(_('Mobility domain'),domain,_('Four hexadecimal digits shared by nodes using fast roaming. Changing this may interrupt connected clients.')),
		field(_('Custom roaming thresholds'),customPolicy,_('Leave disabled to use the recommended policy. Changes apply to all nodes through a reviewed transaction. Association rejection and forced disconnection remain disabled.'))
	] : [
		field(_('Mesh ID'),meshid,_('802.11s backhaul identifier, separate from the client SSID. All managed backhaul radios must use the same identifier.')),
		field(_('Independent SAE passphrase'),meshkey,_('Leave empty to keep the existing wireless backhaul secret, including when switching between wireless and wired preferred modes. A new wireless backhaul generates an independent random secret automatically.')),
		field(_('Backhaul channel'),channel,_('A shared fixed channel for the selected backhaul band. Regulatory limits and DFS waiting periods still apply.')),
		field(_('Channel width'),width,_('All backhaul radios must support this width; a higher width does not guarantee higher throughput.'))
	];
	var editor=E('fieldset',{'class':'mm-editor'},[
		E('div',{'class':'mm-form mm-basic-form'},basic),widgets.details(_('Advanced settings'),[E('div',{'class':'mm-form'},advanced)].concat(page==='wireless' ? [policyFields,networks.element] : []))
	]);
	var pendingId=null,reviewedId=null,sending=false,waiting=false,submissionError=null,latest=c,initialVersion=c.version || 0;
	var saveState=E('span',{'class':'mm-save-state','role':'status','aria-live':'polite'});
	var featureState=E('span',{'class':'mm-muted','role':'status'});
	var save=button(_('Save & Apply'),function() {
		if(sending || !writable || editor.mmLocked)return;
		var invalid=Array.from(editor.querySelectorAll('input,select')).find(function(control) { return !control.checkValidity(); });
		if(invalid) { var details=invalid.closest('details');if(details)details.open=true;invalid.reportValidity();return; }
		var intent=candidate();sending=true;waiting=false;submissionError=null;update(latest);
		return retryBusy('cluster_preflight',[intent,requestId(),needsMaintenance(intent.backhaul)],function() {
			waiting=true;update(latest);
		}).then(function(job) {
			pendingId=job.id;
			return refresh();
		}).catch(function(error) {
			submissionError=widgets.configurationError(error);notify(error);
		}).finally(function() { sending=false;waiting=false;update(latest); });
	},!writable);
	save.classList.replace('cbi-button-neutral','cbi-button-apply');
	var reset=button(_('Reset'),function() { return refresh(true); },!writable);
	function update(next) {
		latest=next.cluster || next;
		var capabilities=next.capabilities || data.capabilities;
		var choice=backhaul.value,modes=[['wired',_('Wired')]];
		(capabilities.backhaul_modes || []).forEach(function(mode){if(mode!=='wired')modes.push([mode,backhaulModeLabel(mode)]);});
		[b.mode,choice].forEach(function(mode){if(mode && !modes.some(function(item){return item[0]===mode;}))modes.push([mode,backhaulModeLabel(mode)]);});
		dom.content(backhaul,modes.map(function(item){return E('option',{value:item[0],selected:item[0]===choice?'':null},[item[1]]);}));
		backhaul.value=choice;
		dom.content(featureState,capabilities.wireless_features_state==='ready' || !capabilities.wireless_features_state ? '' :
			capabilities.wireless_features_state==='unavailable' ? _('Wireless capabilities are unavailable; changes will be preflighted.') :
			_('Checking wireless capabilities; changes will be preflighted.'));
		var job=latest.active, busy=job && ['complete','partial','failed','rolled_back','expired'].indexOf(job.phase)<0;
		if(next.cluster && next.active && ['committed','rolled_back','rollback_conflict','expired'].indexOf(next.active.status)<0)busy=true;
		if(latest.lifecycle && ['complete','failed','partial','cancelled','expired'].indexOf(latest.lifecycle.phase)<0)busy=true;
		var stale=(latest.version || 0)!==initialVersion;
		if(next.cluster && next.mesh_enabled===false)busy=true;
		widgets.lockEditor(editor,!writable || sending || !!busy || stale);
		var drift=next.cluster && next.drift && next.drift.length;
		save.disabled=!writable || !widgets.recoveryReady(capabilities) || sending || !!busy || stale || !!drift;
		save.title=drift ? _('Resolve managed differences on Nodes before applying changes.') : '';
		reset.disabled=sending || !!busy;
		dom.content(saveState,drift ? E('a',{href:L.url('admin','network','mesh-manager','nodes')},[_('Review configuration differences')]) :
			submissionError || (stale ? _('Network configuration changed; reset before editing again.') :
			sending ? waiting ? _('Waiting for the current operation…') : _('Preflighting') : job ? stateLabel(job.phase) : ''));
		if(pendingId && job && job.id===pendingId && job.phase==='ready' && reviewedId!==pendingId) {
			reviewedId=pendingId;reviewCluster(data,latest,job,refresh,writable);
		}
		if(pendingId && job && job.id===pendingId && job.phase==='complete') {
			pendingId=null;window.setTimeout(function() { refresh(true); },0);
		}
	}
	var section=widgets.section(page==='wireless' ? _('Client wireless') : _('Backhaul configuration'),[
		editor,E('div',{'class':'mm-form-actions'},[save,reset,saveState,featureState])
	]);
	section.mmUpdate=update;return section;
}

function reviewCluster(data,c,a,refresh,writable) {
	return retryBusy('status_detail',['cluster','',a.id]).then(function(current) {
		showClusterReview(data,c,current,refresh,writable);
	}).catch(notify);
}
function showClusterReview(data,c,a,refresh,writable) {
	var body=[], members=c.members || [], id=c.identity || {};
	if(a.maintenance)body.push(E('p',{'class':'alert-message warning'},[_('Backhaul changes require every AP to have a verified wired connection. Applying may briefly interrupt the network.')]));
	[{id:id.id,plan:a.root.plan}].concat(a.nodes).forEach(function(n) {
		var member=members.find(function(item) { return item.id===n.id; });
		body.push(E('h4',{},[n.id===id.id ? data.local.board && data.local.board.hostname || _('Controller') : member && member.name || n.id]),
			table([_('Setting'),_('Before'),_('After')],(n.plan && n.plan.ops || []).filter(function(op) { return op.changed!==false; }).map(function(op) {
				return [op.config+'.'+op.section+(op.option ? '.'+op.option : ''),op.before,op.after];
			}),_('No changed fields')));
		(n.plan && n.plan.warnings || []).forEach(function(warning) { body.push(E('p',{'class':'mm-muted'},[warning])); });
		(n.plan && n.plan.errors || []).forEach(function(error) {
			body.push(E('p',{'class':'mm-error'},[widgets.configurationError(error)]));
		});
	});
	if(a.phase==='ready')approvalModal(_('Apply reviewed cluster changes'),body,function() { return call('cluster_apply',a.id,a,true).then(refresh); },writable);
	else widgets.modal(_('All-node preflight'),body.concat([button(_('Close'),function() { ui.hideModal(); })]));
}
function summary(page,data,c,refresh,writable) {
	if(!c)return [];
	var result=[],id=c.identity || {},a=c.active;
	if(page==='nodes'){
		var stop=lifecycle.stopStatus(data,refresh,writable);if(stop)result.push(stop);
		if(id.role==='ap' && data.configured)result.push(widgets.section(_('This device'),[table([_('Node'),_('Status'),_('Mesh'),_('Actions')],[
			[id.name || _('This device'),widgets.status(_('Online'),'good'),lifecycle.state(data),lifecycle.localAction(data,refresh,writable)]
		])]));
	}
	if(page==='overview' && id.role!=='unbound') {
		var online=c.member_counts ? c.member_counts.online : 0;
		var total=c.member_counts ? c.member_counts.total : 0;
		var overview=[[_('Network'),id.name],[_('Mesh role'),id.role==='root' ? id.gateway==='bridge' ? _('Root bridge') : _('Root router') : _('AP node')],
			[_('Network version'),c.version],[_('Management addresses'),data.local.management && data.local.management.addresses ? data.local.management.addresses.map(function(address) { return address.address; }).join(', ') : _('Unavailable')],
			[_('Background services'),widgets.background(data)]];
		overview.unshift([_('Mesh state'),lifecycle.state(data)]);
		if(id.role==='root')overview.splice(4,0,[_('AP nodes'),online+' / '+total]);
		overview.push([_('Configuration'),data.drift.length ? E('a',{href:L.url('admin','network','mesh-manager','nodes')},[
			widgets.status(_('Managed differences: %s').format(data.drift.length),'warning')
		]) : !data.configured ? widgets.status(_('Waiting for first configuration'),'warning') : widgets.status(_('Consistent'),'good')]);
		if(id.joining)overview.push([_('Joining request'),stateLabel(id.joining.status)]);
		result.push(widgets.section(_('Mesh network'),[widgets.facts(overview)]));
		result.push(widgets.section(_('Network topology'),[topology.table()]));
	}
	if(a && ['complete','partial','failed','rolled_back','expired'].indexOf(a.phase)<0 && ['overview','history','wireless','backhaul'].indexOf(page)>=0){
		var inspect=button(a.phase==='ready' ? _('Review & Apply') : _('Inspect all-node changes'),function() { reviewCluster(data,c,a,refresh,writable); },false);
		result.push(widgets.section(_('Cluster transaction'),[
			widgets.status(stateLabel(a.phase),a.phase==='ready' ? 'good' : 'warning'),
			widgets.checkList([[id.name || _('Controller'),stateLabel(a.root.status),a.root.error ? 'error' : 'neutral']].concat(a.nodes.map(function(n) { return [n.name || n.id,stateLabel(n.status),n.error ? 'error' : 'neutral']; })))
		],[inspect,button(_('Roll back cluster change'),function() { return call('cluster_rollback',a.id).then(refresh).catch(notify); },!writable)]));
	}
	if(a && ['partial','failed'].indexOf(a.phase)>=0 && ['wireless','backhaul'].indexOf(page)>=0)result.push(widgets.section(_('Cluster transaction'),[
		widgets.status(stateLabel(a.phase),'error'),widgets.failure(a.failure),
		widgets.checkList([[id.name || _('Controller'),stateLabel(a.root.status),a.root.error ? 'error' : 'neutral']].concat(a.nodes.map(function(n) {
			return [n.name || n.id,stateLabel(n.status),n.error ? 'error' : 'neutral'];
		})))
	]));
	if(page==='nodes' && id.role==='root'){
		var nodes=(c.members || []).filter(function(n){return n.authorized!==false;}).map(function(n) {
			function inspectRepair() {
				if (!n.repair) return showRepair(null);
				return call('status_detail','repair',n.id,n.repair.id).then(showRepair).catch(notify);
			}
			function showRepair(job) {
				var pending = job && ['committed','failed','rolled_back','rollback_conflict','expired'].indexOf(job.status) < 0;
				var body = [widgets.facts([[_('Node'), n.name || n.id], [_('Mesh intent version'), n.version],
					[_('Local transaction version'), n.report && n.report.local_version],
					[_('Configuration repair'), job ? stateLabel(job.status) : _('No repair request')]]),
					E('p', {}, [_('Only managed fields are restored; other settings are preserved')]),
					table([_('Setting'),_('Details')], (n.report && n.report.drift || []).map(function(d) {
						return [d.config+'.'+d.section+(d.option ? '.'+d.option : ''),_('Managed value changed outside Mesh Manager')];
					}), n.report && n.report.drift ? _('No configuration drift reported') : _('Unavailable'))];
				if (job && job.error) body.push(widgets.failure(job.error));
				if (job && (job.conflicts || []).length) body.push(table([_('Setting'),_('Details')],job.conflicts.map(function(conflict) {
					return [conflict.path,_('External change preserved; manual recovery required')];
				})));
				if (job && job.status === 'ready') {
					body.push(table([_('Setting'),_('Before'),_('After')],job.plan.ops.filter(function(op) { return op.changed!==false; }).map(function(op) {
						return [op.config+'.'+op.section+(op.option ? '.'+op.option : ''),op.before,op.after];
					}),_('No changed fields')));
					body.push(button(_('Cancel repair'),function() { return call('node_repair_rollback',n.id,job.id).then(function() { ui.hideModal(); return refresh(); }).catch(notify); },!writable));
					approvalModal(_('Resend managed configuration'),body,function() {
						return call('node_repair_apply',n.id,job.id,job.plan,true).then(refresh);
					},writable);
				} else {
					body.push(E('div',{'class':'mm-actions'},[
						button(_('Close'),function() { ui.hideModal(); }),
						pending ? button(_('Cancel repair'),function() { return call('node_repair_rollback',n.id,job.id).then(function() { ui.hideModal(); return refresh(); }).catch(notify); },!writable) :
							button(_('Request repair preview'),function() { return call('node_repair',n.id,requestId()).then(function() { ui.hideModal(); return refresh(); }).catch(notify); },!writable || !n.authorized)
					]));
					widgets.modal(_('Resend managed configuration'),body);
				}
			}
			var repairButton=button(_('Restore configuration'),inspectRepair,!n.authorized || n.mesh_paused);
			repairButton.classList.add('mm-node-repair');
			repairButton.title=_('Resend managed configuration');
			var online=n.authorized && n.online, controls=E('div',{'class':'mm-actions mm-node-actions'},[
				repairButton,
				button(_('Rename'),function() {
					var value=input(n.name),progress=E('p',{role:'status'}),cancelled=false,renameDialog,approvalDialog;
					value.required=true;value.maxLength=64;
					function owns(dialog,anchor) {
						// LuCI hides and reuses the same modal DOM. Visibility plus this
						// operation's content anchor is required to retain ownership.
						if(cancelled || !document.body.classList.contains('modal-overlay-active') ||
							!dialog || !dialog.isConnected || document.querySelector('#modal_overlay > .modal')!==dialog ||
							!dialog.contains(anchor)) { cancelled=true;return false; }
						return true;
					}
					function previewActive(){return owns(renameDialog,value);}
					function approvalActive(){return owns(approvalDialog,progress);}
					function waiting(){progress.textContent=_('Waiting for the current operation…');}
					var preview=button(_('Preview name change'),function() {
						if(!previewActive() || !value.reportValidity())return;preview.disabled=true;
						return retryBusy('node_rename_preview',[n.id,value.value],waiting,0,previewActive).then(function(plan) {
							if(!previewActive())return;
							var request=requestId();
							progress.textContent='';
							approvalDialog=approvalModal(_('Rename'),[widgets.facts([[_('Before'),plan.previous_name],[_('After'),plan.name]]),progress],function() {
								return retryBusy('node_rename',[request,plan,true],waiting,0,approvalActive).then(function() {
									ui.addNotification(null,E('p',{},[_('Node name saved.')]),'info');return refresh();
								});
							},writable,_('I confirm the displayed name change'),{active:approvalActive,cancel:function(){cancelled=true;}});
						}).catch(function(error){if(previewActive() && error.code!=='job_cancelled')notify(error);})
							.finally(function(){preview.disabled=cancelled || !writable;});
					},!writable);
					renameDialog=widgets.modal(_('Node name'),[field(_('Node name'),value),progress,E('div',{'class':'mm-actions mm-dialog-actions'},[
						button(_('Cancel'),function() { if(!previewActive())return;cancelled=true;ui.hideModal(); }),preview])]);
				},!writable || !n.authorized),
				button(_('Revoke identity'),function() { approvalModal(_('Revoke node identity'),[
					E('p',{},[n.name+' '+n.id]),E('p',{'class':'mm-muted'},[_('Disable this AP’s Mesh and verify restoration before revoking its identity. Revocation does not rotate the shared wireless backhaul key.')])
				],function() { return call('node_revoke',n.id).then(refresh); },writable); },!writable || !n.authorized)
			]);
			controls.appendChild(lifecycle.nodeAction(data,n,refresh,writable));
			var backhaul=n.report && n.report.backhaul, quality=backhaul && backhaul.quality;
			var drift=n.report && Array.isArray(n.report.drift) ? n.report.drift.length : null;
			var first=n.report && n.report.configured===false, configuration=n.report && n.report.configuration;
			var componentBlocked=first && configuration && configuration.error==='wireless_control_incompatible';
			return [
				E('div',{},[
					E('div',{'class':'mm-node-name',title:n.id},[n.name || n.id]),
					E('div',{'class':'mm-node-model'},[n.report && n.report.model || _('Unavailable')])
				]),
				widgets.status(!n.authorized ? _('Revoked') : online ? _('Online') : _('Offline'),!n.authorized ? 'error' : online ? 'good' : 'warning'),
				E('div',{'class':'mm-node-meta'},[
					pathLabel(backhaul && backhaul.active),
					quality ? E('small',{},[quality.signal_dbm+' dBm / '+quality.phy_rate_mbps+' Mb/s']) : E('span')
				]),
				E('span',{'class':'mm-node-version',title:_('Mesh intent version')},[String(n.version || 0)]),
				E('div',{'class':'mm-node-config'},[
					widgets.status(n.mesh_paused ? _('Disabled') : componentBlocked ? _('Firmware components need repair') : first ? _('Waiting for first configuration') : drift == null ? _('Unavailable') : drift ? _('Managed differences: %s').format(drift) : _('Consistent'),n.mesh_paused || drift == null ? 'neutral' : first || drift ? 'warning' : 'good'),
					first && configuration && configuration.error ? widgets.help(widgets.configurationError({code:configuration.error})) : E('span'),
					!online && n.report ? E('small',{},[_('Last report')]) : E('span'),
					n.repair && n.repair.status!=='committed' ? E('small',{},[stateLabel(n.repair.status)]) : E('span')
				]), controls
			];
		});
		if(data.configured)nodes.unshift([
			E('div',{},[E('div',{'class':'mm-node-name'},[id.overrides && id.overrides.name || data.local.board && data.local.board.hostname || id.name]),
				E('div',{'class':'mm-node-model'},[id.gateway==='bridge' ? _('Root bridge') : _('Root router')])]),
			widgets.status(_('Online'),'good'),'-',String(c.version || 0),
			lifecycle.state(data),
			E('div',{'class':'mm-actions mm-node-actions'},[lifecycle.localAction(data,refresh,writable)])
		]);
		var nodeTable=table([_('Node'),_('Status'),_('Backhaul'),_('Version'),_('Configuration'),_('Actions')],nodes,_('No AP nodes joined'));
		if(nodes.length)nodeTable.querySelector('table').classList.add('mm-node-list');
		result.push(widgets.section(_('Nodes'),[nodeTable]));
		var revoked=(c.revocations || []).concat((c.members || []).filter(function(n){return n.authorized===false;}).map(function(n){
			return {id:n.id,name:n.name,restoration_confirmed:n.restoration_confirmed,removed:n.removed};
		}));
		if(revoked.length)result.push(E('details',{'class':'mm-revoked','data-mm-detail':'revoked'},[
			E('summary',{},[_('Revocation records (%s)').format(revoked.length)]),
			table([_('Node'),_('Revoked at'),_('Configuration restoration')],revoked.map(function(n){return [
				E('span',{title:n.id},[n.name || n.id]),n.removed ? new Date(n.removed*1000).toLocaleString() : _('Unavailable'),
				widgets.status(n.restoration_confirmed ? _('Verified') : _('Needs verification'),n.restoration_confirmed ? 'neutral' : 'warning')
			];}))
		]));

	}
	if(page==='history' && id.role==='root') result.push(history.section('cluster-history', 'cluster', _('Cluster changes'), [
		_('Time'), _('Status'), _('Mesh intent version'), _('Transaction'), _('Details')
	], function(h) {
		return [h.timestamp ? new Date(h.timestamp*1000).toLocaleString() : '-',
			widgets.status(stateLabel(h.phase),h.phase==='complete' ? 'good' : h.phase==='failed' ? 'error' : 'warning'),
			h.version,E('code',{title:h.id},[h.id]),widgets.failure(h.failure, 'cluster:' + h.id) || '-'];
	},_('No cluster changes yet'),{writable:writable,refresh:refresh}));
	if(page==='history' && id.role==='root' && data.history_counts.repair) result.push(history.section('node-repairs', 'repair', _('Node repairs'), [
		_('Time'),_('Node'),_('Status'),_('Mesh intent version'),_('Details')
	], function(job) {
		var member = (c.members || []).find(function(node) { return node.id === job.node_id; });
		var conflicts = (job.conflicts || []).map(function(conflict) { return conflict.path; }).join(', ');
		return [new Date(job.timestamp*1000).toLocaleString(), E('span', { title: job.node_id }, [member && member.name || (job.node_id || '').slice(0, 8)]),
			widgets.status(stateLabel(job.status), job.status==='committed' ? 'good' : ['failed','rollback_conflict'].indexOf(job.status)>=0 ? 'error' : 'warning'), job.version,
			widgets.failure(conflicts ? 'rollback_conflict: ' + conflicts : job.error, 'node-repair:' + job.id) || (job.purpose === 'overrides' ? _('Local settings') : '-')];
	},_('No node repairs'),{writable:writable,refresh:refresh}));
	if(page==='history') {
		var meshHistory=lifecycle.history(data,refresh,writable);
		if(meshHistory)result.push(meshHistory);
	}
	if(page==='history' && id.role==='root' && data.history_counts.metadata) result.push(history.section('node-name-history','metadata',_('Node name changes'),[_('Time'),_('Before'),_('After'),_('Status')],function(row) {
			return [new Date(row.timestamp*1000).toLocaleString(),E('span',{title:row.node_id},[row.previous_name]),row.name,
				widgets.status(_('Committed'),'good')];
		},_('No node name changes'),{writable:writable,refresh:refresh}));
	if(page==='diagnostics' && c.agent && !c.agent.ok) result.push(E('p',{'class':'alert-message warning'},[_('Node agent error')+': '+c.agent.error]));
	return result;
}
return baseclass.extend({
	localSettingRows:localSettingRows,
	summary:function(page,data,refresh,writable) { return summary(page,data,data.cluster,refresh,writable); },
	forms:function(page,data,refresh,writable) {
		var c=data.cluster;if(!c)return E('div');
		if((c.identity.role==='unbound' || c.identity.role==='root' && !data.configured) && page==='overview')return setup(data,c,refresh,writable);
		if(c.identity.role==='root' && (page==='wireless' || page==='backhaul'))return unifiedForm(data,c,refresh,writable,page);
		if(c.identity.role!=='unbound' && page==='nodes'){
			var localFacts=widgets.facts([
				[_('Mesh intent version'),c.version],[_('Local transaction version'),data.version]
			]);
			var fields=localFields(data,c.identity), editor=E('fieldset',{'class':'mm-editor'},[
				E('div',{'class':'mm-form mm-basic-form'},[fields.fields[0]]),
				widgets.details(_('Advanced settings'),[localFacts,E('div',{'class':'mm-form'},fields.fields.slice(1))])
			]);
			widgets.lockEditor(editor,!writable);
			var save=button(_('Preview and apply'),function() {
				return localSettingsPreview(fields.value(), data, refresh, writable);
			},!writable || !data.mesh_enabled);
			save.classList.replace('cbi-button-neutral','cbi-button-save');
			var addresses=data.local.management && data.local.management.addresses || [];
			var localRole=c.identity.role==='ap' ? _('AP node') : c.identity.gateway==='bridge' ? _('Root bridge') : _('Root router');
			var firstConfiguration=E('div',{'class':'mm-first-configuration','role':'status'});
			var section=widgets.section(_('Local settings'),[
				firstConfiguration,
				E('p',{'class':'mm-local-summary'},[data.local.board && data.local.board.model || _('Unavailable'),' · ',localRole,' · ',addresses.map(function(address) { return address.address; }).join(', ')]),
				editor,E('div',{'class':'mm-form-actions'},[
					save,button(_('Reset'),function() { return refresh(true); })
				])
			]);
			section.mmUpdate=function(next) {
				var e=next.cluster && next.cluster.identity && next.cluster.identity.enrollment;
				dom.content(firstConfiguration,c.identity.role==='ap' && e && e.enabled ?
					[widgets.status(enrollmentLabel(e.status),'warning'),
					(e.status==='configuration_blocked' && e.error ? widgets.status(widgets.configurationError({code:e.error}),'warning') :
					widgets.failure(e.error,'first-configuration')) || E('span')] : []);
				var local=next.active && ['committed','rolled_back','rollback_conflict','expired'].indexOf(next.active.status)<0;
				var active=next.cluster && next.cluster.active;
				var busy=local || active && ['complete','partial','failed','rolled_back','expired'].indexOf(active.phase)<0;
				widgets.lockEditor(editor,!writable || !!busy || !next.mesh_enabled);
				save.disabled=!writable || !!busy || !next.mesh_enabled;
			};
			section.mmUpdate(data);
			return section;
		}
		return E('div');
	}
});
