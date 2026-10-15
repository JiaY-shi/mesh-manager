// SPDX-License-Identifier: GPL-2.0-only
'use strict';
'require baseclass';
'require rpc';
'require ui';
'require poll';
'require dom';
'require mesh_manager.cluster as cluster';
'require mesh_manager.widgets as widgets';
'require mesh_manager.slow_rpc as slow_rpc';
'require mesh_manager.history as history';
'require mesh_manager.diagnostics as diagnostics';
'require mesh_manager.clients as clientView';

var endpoints = {};
[['status', ['view', 'history_mode']], ['diagnostics', []], ['preview', ['intent']],
 ['stage', ['intent', 'request_id', 'takeover', 'approval']], ['apply', ['transaction_id']],
 ['confirm', ['transaction_id']], ['rollback', ['transaction_id']],
 ['release', ['request_id', 'takeover']], ['mesh_confirm', ['transaction_id']], ['repair_preview', []],
 ['repair_stage', ['request_id', 'takeover', 'approval']], ['repair_confirm', ['transaction_id']], ['local_overrides_confirm', ['transaction_id']]].forEach(function(spec) {
	endpoints[spec[0]] = rpc.declare({ object: 'mesh-manager', method: spec[0], params: spec[1], reject: true });
});
endpoints.repair_preview = slow_rpc.preview;
endpoints.local_overrides_confirm=function(transaction_id) {
	return slow_rpc.action('local_overrides_confirm',{transaction_id:transaction_id});
};
endpoints.mesh_confirm=function(transaction_id) {
	return slow_rpc.action('mesh_confirm',{transaction_id:transaction_id});
};
endpoints.diagnostics = rpc.declare({object:'mesh-manager.diag',method:'export',params:[],reject:true});

function call(method) {
	return endpoints[method].apply(null, Array.prototype.slice.call(arguments, 1)).then(function(result) {
		if (!result || result.ok !== true) {
			var error = new Error(result && result.error ? result.error.message : _('Backend unavailable'));
			error.code = result && result.error && result.error.code;
			if (['local_overrides_confirm','mesh_confirm'].indexOf(method)>=0 && ['request_timeout','backend_unavailable'].indexOf(error.code)>=0)error.code='outcome_unknown';
			if (error.code === 'outcome_unknown') error.message = _('Could not confirm the result. Check the latest local change before retrying.');
			if (error.code === 'request_timeout') error.message = _('Preview timed out. Check the controller connection and try again.');
			if (error.code === 'backend_unavailable') error.message = _('Backend unavailable');
			if (error.code === 'busy') error.message = _('Manager is busy; retry later.');
			if (error.code === 'job_expired') error.message = _('Preview expired after a service restart or inactivity. Please preview again.');
			throw error;
		}
		return result.data;
	});
}
var transactionActions = Object.create(null);
function transactionAttempt(method, id, attempt) {
	attempt=attempt || 0;
	return call(method,id).catch(function(error) {
		if(error.code==='outcome_unknown')error.message=_('Could not confirm the result. Check the latest local change before retrying.');
		// These operations are idempotent for one existing transaction. Retry
		// explicit lock contention only; an unknown/timeout result stays visible.
		if(error.code!=='busy' || attempt>=4)throw error;
		return new Promise(function(resolve) { window.setTimeout(resolve,250*(attempt+1)); }).then(function() {
			return transactionAttempt(method,id,attempt+1);
		});
	});
}
function transactionAction(method, id) {
	var existing = transactionActions[id];
	if (existing) {
		if (existing.method === method) return existing.promise;
		var error = new Error(_('Manager is busy; retry later.')); error.code = 'busy';
		return Promise.reject(error);
	}
	var operation = transactionActions[id] = { method: method };
	document.querySelectorAll('.mm-transaction').forEach(function(section) {
		if (section.getAttribute('data-mm-transaction') !== id) return;
		section.setAttribute('aria-busy', 'true');
		section.querySelectorAll('button').forEach(function(control) { control.disabled = true; });
	});
	operation.promise = transactionAttempt(method,id).finally(function() {
		if (transactionActions[id] === operation) delete transactionActions[id];
	});
	return operation.promise;
}
function loadStatus(view, attempt) {
	return call('status', view === 'clients' ? 'clients_brief' : view, view === 'history' ? 'paged' : '').catch(function(error) {
		if (attempt >= 12 || (error.code !== 'busy' &&
			!/another request|request in progress|\bbusy\b/i.test(error.message || ''))) throw error;
		return new Promise(function(resolve) { window.setTimeout(resolve, Math.min(1000, 200 * (attempt + 1))); }).then(function() {
			return loadStatus(view, attempt + 1);
		});
	});
}
function text(value) { return value == null ? '-' : typeof value === 'object' ? JSON.stringify(value) : String(value); }
var table = widgets.table;
function requestId() {
	var bytes = new Uint8Array(16);
	window.crypto.getRandomValues(bytes);
	return Array.from(bytes).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
}
function button(label, action, disabled) {
	return E('button', { 'class': 'cbi-button cbi-button-neutral', type: 'button', disabled: disabled || null, click: ui.createHandlerFn(null, action) }, label);
}
function notify(error) { ui.addNotification(null, E('p', {}, [widgets.configurationError(error)]), 'error'); }
function stateLabel(status) {
	var labels = { staged: _('Staged'), apply_requested: _('Apply queued'), applying: _('Applying'), awaiting_confirm: _('Awaiting confirmation'), committed: _('Committed'), rollback_requested: _('Rollback queued'), rolling_back: _('Rolling back'), rolled_back: _('Rolled back'), rollback_conflict: _('Rollback conflict'), expired: _('Expired') };
	return labels[status] || status;
}
function role(intent) { return !intent ? _('Not managed') : intent.controller ? intent.gateway === 'router' ? _('Root router') : _('Root bridge') : _('AP node'); }
function terminal(status) { return ['committed', 'rolled_back', 'rollback_conflict', 'expired'].indexOf(status) >= 0; }
function healthLabel(name) {
	var labels = {
		lan_dhcp_configuration: _('LAN DHCP configuration'), lan_dhcp_service: _('LAN DHCP service'),
		lan_ipv6_service: _('LAN IPv6 service'), management_interface: _('Management interface'),
		management_protocol: _('Management address mode'), management_address: _('Management address'),
		expected_configuration: _('Managed configuration'), wan_interface: _('WAN connection'),
		backhaul_mesh: _('Wireless backhaul'), backhaul_peer_acl: _('Mesh peer authorization'),
		usteer_stopped: _('Roaming assistance stopped'), usteer_running: _('Roaming assistance running'),
		usteer_control_interfaces: _('Roaming coordination interfaces')
	};
	if (labels[name]) return labels[name];
	if (name.indexOf('ap_') === 0) return _('Wi-Fi access point (%s)').format(name.slice(3));
	// Retain unsupported/backend-specific names as inspectable technical evidence.
	return name;
}
function pathLabel(path) {
	return path === 'wired' ? _('Wired') : path === 'wireless' ? _('Wireless') :
		path === 'none' ? _('No active path') : _('Unknown');
}
function backhaulModeLabel(mode) {
	return mode === 'wired' ? _('Wired only') : mode === 'auto' ? _('Wired preferred, wireless standby') :
		mode === 'wireless' ? _('802.11s wireless') : _('Unavailable');
}

function managementChanged(ops) {
	var fields = {};
	ops.forEach(function(op) {
		if(op.config==='network' && op.section==='lan' && ['proto','ipaddr','netmask'].indexOf(op.option)>=0)fields[op.option]=op;
	});
	if(fields.proto && fields.proto.changed!==false && fields.proto.before!==fields.proto.after)return true;
	if(!['ipaddr','netmask'].some(function(key){return fields[key] && fields[key].changed!==false;}))return false;
	if(!fields.ipaddr)return true;
	function addresses(side) {
		var address=fields.ipaddr[side],mask=fields.netmask && fields.netmask[side],prefix=32;
		if(mask!=null) {
			var octets=String(mask).split('.'),bits=[0,128,192,224,240,248,252,254,255];
			if(octets.length!==4 || octets.some(function(o){return bits.indexOf(Number(o))<0;}))return null;
			prefix=octets.reduce(function(sum,o){return sum+bits.indexOf(Number(o));},0);
		}
		if(address==null)return [];
		return (Array.isArray(address)?address:[address]).map(function(item){
			var parts=String(item).split('/');return parts[0]+'/'+(parts.length===2?Number(parts[1]):prefix);
		}).sort();
	}
	var before=addresses('before'),after=addresses('after');
	return !before || !after || JSON.stringify(before)!==JSON.stringify(after);
}

function transaction(data, refresh, writable, page) {
	var a = data.active;
	if (!a) return E('div');
	if (terminal(a.status)) {
		var job=data.cluster && data.cluster.lifecycle;
		if(['nodes','history'].indexOf(page)<0 || page==='nodes' && job && job.root.transaction_id===a.id)return E('div');
		return widgets.section(_('Latest local change'),[
			widgets.status(stateLabel(a.status),a.status==='committed' ? 'good' : a.status==='rollback_conflict' ? 'error' : 'warning'),
			a.failure ? widgets.failure(a.failure,'active:'+a.id) : E('span'),
			(a.conflicts || []).length ? widgets.details(_('Conflicts'),[table([_('Setting'),_('Details')],a.conflicts.map(function(c){
				return [c.path,_('External change preserved; manual recovery required')];
			}))]) : E('span')
		]);
	}
	var actions = [], pending = a.status === 'awaiting_confirm', inFlight = !!transactionActions[a.id];
	function perform(method) {
		return transactionAction(method,a.id).then(refresh).catch(function(error) { notify(error); return refresh(); });
	}
	var repair = data.cluster && data.cluster.local_repair;
	var controlledRepair = a.kind === 'repair' && repair && !repair.manual && repair.transaction_id === a.id;
	var mesh = data.cluster && data.cluster.local_mesh;
	var controlledMesh = a.mesh_enabled != null && mesh && !mesh.manual && mesh.transaction_id === a.id;
	var addressChanged = managementChanged(a.ops);
	var currentAddresses = data.local.management ? data.local.management.addresses : [];
	var onManagementAddress = currentAddresses.some(function(addr) { return addr.address === window.location.hostname; });
	if (a.status === 'staged') actions.push(button(_('Apply candidate'), function() { return perform('apply'); }, inFlight || !writable || !widgets.recoveryReady(data)));
	if (pending && !controlledRepair && !controlledMesh && !a.local_confirmation) actions.push(button(_('Confirm'), function() { return perform(a.mesh_enabled != null ? 'mesh_confirm' : a.kind === 'repair' ? 'repair_confirm' : a.kind === 'overrides' ? 'local_overrides_confirm' : 'confirm'); }, inFlight || !writable || !data.health || !data.health.ok || a.remaining <= 0 || addressChanged && !onManagementAddress));
	if (!terminal(a.status)) actions.push(button(_('Roll back'), function() { return perform('rollback'); }, inFlight || !writable));
	return E('section', { 'class': 'mm-transaction', 'data-mm-transaction': a.id, 'aria-busy': String(inFlight) }, [
		a.kind === 'repair' ? E('h4', {}, [_('Configuration repair')]) : a.kind === 'overrides' ? E('h4', {}, [_('Local settings')]) : E('div'),
		E('strong', {}, [stateLabel(a.status)]), E('span', {}, [' ' + a.id]),
		inFlight ? E('span', { 'class': 'spinning' }, [_('Processing request…')]) : E('span'),
		pending && a.local_confirmation ? E('p', {}, [_('The AP will finish restoring after local LAN health checks pass. The controller result updates when contact resumes.')]) :
			(controlledRepair || controlledMesh) && pending ? E('p', {}, [_('Waiting for controller health confirmation')]) : E('div'),
		a.failure ? widgets.failure(a.failure, 'active:' + a.id) : E('div'),
		(a.conflicts || []).length ? table([_('Setting'), _('Details')], a.conflicts.map(function(c) {
			return [c.path, _('External change preserved; manual recovery required')];
		})) : E('div'),
		pending ? E('p', {}, _('Automatic rollback in %s seconds').format(a.remaining)) : E('div'),
		pending && addressChanged && !onManagementAddress ? E('p', {}, [_('Management address'), ': '].concat(currentAddresses.map(function(addr) { var url = new URL(window.location.href); url.hostname = addr.address; return E('a', { href: url.href }, [addr.address]); }))) : E('div'),
		a.kind==='overrides' && a.local_settings ? table([_('Setting'),_('Before'),_('After')],cluster.localSettingRows(a.local_settings),_('No changed fields')) : a.status === 'staged' ? table([_('Setting'), _('Before'), _('After')], a.ops.filter(function(op) { return op.changed !== false; }).map(function(op) { return [op.config + '.' + op.section + (op.option ? '.' + op.option : ''), text(op.before), text(op.after)]; })) : E('div'),
		data.health ? table([_('Health check'), _('Result')], data.health.checks.map(function(c) { return [healthLabel(c.name), c.ok ? _('Passed') : _('Not ready')]; })) : E('div'),
		E('div', { 'class': 'mm-actions' }, actions)
	]);
}

function repairPreview(data, refresh, writable) {
	var label=data.cluster && data.cluster.identity.role==='root' ? _('Restore managed configuration') : _('Restore Root configuration');
	var progress=E('p',{},[_('Preview queued')]), cancelled=false;
	var control={progress:function(state){progress.textContent=state==='running' ? _('Preparing configuration preview') : _('Preview queued');}};
	widgets.modal(label,[progress,E('div',{'class':'mm-actions'},[button(_('Cancel'),function(){
		cancelled=true;ui.hideModal();return control.cancel ? control.cancel().catch(notify) : Promise.resolve();
	})])]);
	return call('repair_preview',control).then(function(plan) {
		if(cancelled)return;
		var approve = E('input', { type: 'checkbox' }), sending = false;
		var apply = button(label, function() {
			if (!approve.checked || sending || !writable || plan.errors.length) return;
			sending = true; apply.disabled = true;
			return call('repair_stage', requestId(), true, plan).then(function(a) {
				return call('apply', a.id);
			}).then(function() { ui.hideModal(); return refresh(); }).catch(function(error) {
				approve.checked = false; sending = false; apply.disabled = true;
				notify(new Error(error.code === 'preview_changed' ? _('Repair preview changed; close this dialog and review again.') : error.message));
			});
		}, true);
		approve.addEventListener('change', function() {
			apply.disabled = sending || !approve.checked || !writable || plan.errors.length > 0 || !widgets.recoveryReady(data);
		});
		widgets.modal(label, [
			widgets.facts([[_('Mesh intent version'), plan.root_version], [_('Local transaction version'), plan.version]]),
			E('p', {}, [_('Only managed fields are restored; other settings are preserved')]),
			E('p', {}, [_('Rollback restores the values present before this repair')]),
			E('ul', {}, plan.errors.map(function(error) { return E('li', { 'class': 'mm-error' }, [
				_('Repair requires manual review'), ': ', widgets.configurationError(error)
			]); })),
			table([_('Setting'), _('Before'), _('After')], plan.ops.filter(function(op) { return op.changed !== false; }).map(function(op) {
				return [op.config + '.' + op.section + (op.option ? '.' + op.option : ''), text(op.before), text(op.after)];
			}), _('No changed fields')),
			E('label', { 'class': 'mm-approval' }, [approve, ' ', _('I approve restoring the displayed managed fields')]),
			E('div', { 'class': 'mm-actions' }, [button(_('Cancel'), function() { ui.hideModal(); }), apply])
		]);
	}).catch(function(error){
		if(cancelled || error.code==='job_cancelled')return;
		ui.hideModal();notify(error);
	});
}

function wizard(data, refresh, writable) {
	var current = data.intent, radios = data.capabilities.radios || [];
	var name = E('input', { type: 'text', maxlength: 64, value: current ? current.name : data.local.board ? data.local.board.hostname : 'OpenWrt' });
	var selectedRole = current ? (current.controller ? current.gateway === 'router' ? 'root-router' : 'root-bridge' : 'ap') : 'ap';
	var mode = E('select', {}, [['root-router', _('Root router')], ['root-bridge', _('Root bridge')], ['ap', _('AP node')]].map(function(item) { return E('option', { value: item[0], selected: selectedRole === item[0] ? '' : null }, item[1]); }));
	var protocol = E('select', {}, [['dhcp', _('Upstream DHCP')], ['static', _('Static address')]].map(function(item) { return E('option', { value: item[0], selected: current && current.management.protocol === item[0] ? '' : null }, item[1]); }));
	var address = E('input', { type: 'text', value: current && current.management.address || data.local.management && data.local.management.addresses[0] && data.local.management.addresses[0].address || '192.168.8.1' });
	var netmask = E('input', { type: 'text', value: current && current.management.netmask || '255.255.255.0' });
	var enabled = E('input', { type: 'checkbox', checked: current && current.wifi.enabled ? '' : null });
	var ssid = E('input', { type: 'text', maxlength: 32, value: current && current.wifi.ssid || '' });
	var encryption = E('select', {}, [E('option', { value: 'psk2' }, 'WPA2-PSK'), E('option', { value: 'sae-mixed', disabled: !data.capabilities.sae || null, selected: current && current.wifi.encryption === 'sae-mixed' ? '' : null }, 'WPA2/WPA3')]);
	var key = E('input', { type: 'password', maxlength: 63, autocomplete: 'new-password', placeholder: _('Enter a new passphrase') });
	var choices = radios.map(function(r) { return { name: r.name, input: E('input', { type: 'checkbox', checked: current && current.wifi.radios.indexOf(r.name) >= 0 ? '' : null }) }; });
	var field = widgets.field;
	function visibility() {
		if (mode.value === 'root-router') protocol.value = 'static';
		protocol.disabled = mode.value === 'root-router';
		address.disabled = netmask.disabled = protocol.value !== 'static';
		ssid.disabled = key.disabled = encryption.disabled = !enabled.checked;
		choices.forEach(function(c) { c.input.disabled = !enabled.checked; });
	}
	mode.addEventListener('change', visibility); protocol.addEventListener('change', visibility); enabled.addEventListener('change', visibility);
	visibility();
	function intent() {
		return { schema: 1, name: name.value, controller: mode.value !== 'ap', gateway: mode.value === 'root-router' ? 'router' : 'bridge', backhaul: 'wired',
			management: { interface: 'lan', protocol: protocol.value, address: address.value, netmask: netmask.value },
			wifi: { enabled: enabled.checked, ssid: ssid.value, encryption: encryption.value, key: key.value, radios: choices.filter(function(c) { return c.input.checked; }).map(function(c) { return c.name; }) } };
	}
	function previewCandidate() {
		var candidate = intent();
		return call('preview', candidate).then(function(plan) {
			var approve = E('input', { type: 'checkbox' });
			var apply = button(_('Approve takeover and apply'), function() {
				if (!approve.checked) return;
				return call('stage', candidate, requestId(), true, plan).then(function(a) { return call('apply', a.id); }).then(function() { ui.hideModal(); return refresh(); }).catch(notify);
			}, true);
			approve.addEventListener('change', function() { apply.disabled = !approve.checked || plan.errors.length > 0 || !writable || !widgets.recoveryReady(data); });
			widgets.modal(_('Change preview'), [
				E('ul', {}, plan.errors.map(function(e) { return E('li', { 'class': 'mm-error' }, [widgets.configurationError(e)]); })),
				E('ul', {}, plan.conflicts.map(function(c) { return E('li', {}, [c.message + ': ' + c.section]); })),
				E('ul', {}, plan.warnings.map(function(w) { return E('li', {}, [w]); })),
				table([_('Setting'), _('Before'), _('After')], plan.ops.filter(function(op) { return op.changed !== false; }).map(function(op) { return [op.config + '.' + op.section + (op.option ? '.' + op.option : ''), text(op.before), text(op.after)]; }), _('No changed fields; intent ownership will still be recorded')),
				E('label', { 'class': 'mm-approval' }, [approve, ' ', _('I approve configuration takeover and understand automatic rollback')]),
				E('div', { 'class': 'mm-actions' }, [button(_('Cancel'), function() { ui.hideModal(); }), apply])
			]);
		}).catch(notify);
	}
	return E('section', { 'class': 'cbi-section mm-wizard' }, [
		E('h3', {}, _('Local configuration')),
		E('div', { 'class': 'mm-form mm-basic-form' }, [field(_('Node name'), name), field(_('Role'), mode), field(_('SSID'), ssid), field(_('Passphrase'), key)]),
		widgets.details(_('Advanced settings'), [E('div', { 'class': 'mm-form' }, [
			field(_('Management address'), protocol), field(_('IPv4 address'), address), field(_('Netmask'), netmask),
			field(_('Manage wireless AP'), enabled), field(_('Encryption'), encryption),
			field(_('Local radios'), E('div', { 'class': 'mm-radio-list' }, choices.map(function(c) { return E('label', {}, [c.input, ' ', c.name]); })))
		])]),
		E('div', { 'class': 'mm-actions' }, [button(_('Preview changes'), previewCandidate, !writable)])
	]);
}

function content(page, data, refresh, writable) {
	var result = [], cap = data.capabilities;
	result = result.concat(cluster.summary(page, data, refresh, writable));
	if(['overview','diagnostics'].indexOf(page)>=0)result.push(diagnostics.attention(data,page==='diagnostics'));
	if (!widgets.recoveryReady(cap) && (!data.attention || !data.mesh_enabled || ['overview','diagnostics'].indexOf(page)<0)) result.push(E('p', { 'class': 'alert-message warning' }, _('Recovery service unavailable. Configuration changes are blocked.')));
	if(!data.active || data.active.kind!=='repair' || page==='nodes' || page==='history')result.push(transaction(data, refresh, writable,page));
	if (data.controller_recovery && ['overview','nodes'].indexOf(page)>=0) {
		var recovery=data.controller_recovery, completed=recovery.status==='committed' && recovery.health_confirmed===true && !(recovery.conflicts || []).length;
		var finished=terminal(recovery.status);
		result.push(widgets.section(_('Controller loss recovery'),[
			E('p',{},completed ? _('Mesh was automatically disabled after losing authenticated controller contact. Connect to LAN using the restored management address to configure this device.') : finished ? _('Automatic restoration could not be verified. Check the transaction result, configuration conflicts and diagnostics.') : _('Controller contact was lost. The AP is restoring its original LAN configuration.')),
			widgets.status(stateLabel(recovery.status),finished && !completed || (recovery.conflicts || []).length ? 'warning' : completed ? 'good' : 'neutral'),
			(recovery.conflicts || []).length ? table([_('Setting'),_('Details')],recovery.conflicts.map(function(item){return [item.path,_('External change preserved; manual recovery required')];})) : E('div')
		]));
	}
	var restoring=data.active && data.active.kind==='release' && ['applying','awaiting_confirm'].indexOf(data.active.status)>=0;
	if (data.drift.length && page==='nodes' && !restoring) {
		var identity=data.cluster && data.cluster.identity, managed=identity && ['ap','root'].indexOf(identity.role)>=0;
		var busy = data.active && !terminal(data.active.status);
		var active=data.cluster && data.cluster.active;
		if(active && ['complete','partial','failed','rolled_back','expired'].indexOf(active.phase)<0)busy=true;
		if(identity && identity.role==='root' && (data.cluster.members || []).some(function(node) {
			return node.repair && ['committed','failed','rolled_back','rollback_conflict','expired'].indexOf(node.repair.status)<0;
		}))busy=true;
		result.push(widgets.section(_('Configuration drift'), [
			E('p',{'class':'mm-muted'},[_('Managed differences: %s').format(data.drift.length)]),
			widgets.details(_('Show differences'),[table([_('Setting'),_('Details')],data.drift.map(function(d) {
				return [widgets.setting(d),_('Managed value changed outside Mesh Manager')];
			}))])
		], managed ? [widgets.help(_('Restore only the managed fields to the saved controller configuration. Review the preview first. Unconfirmed repairs restore the pre-repair values; later external changes are preserved and reported as conflicts.')),
			button(identity.role==='root' ? _('Restore managed configuration') : _('Restore Root configuration'), function() { return repairPreview(data, refresh, writable); },
				!writable || !widgets.recoveryReady(cap) || busy)] : null));
	}
	if (page === 'overview') {
		var controller = data.cluster && data.cluster.identity, managedRole = controller && controller.role !== 'unbound' ? controller.role === 'root' ? controller.gateway === 'bridge' ? _('Root bridge') : _('Root router') : _('AP node') : role(data.intent);
		if (!controller || controller.role === 'unbound') result.push(widgets.section(_('Network status'), [widgets.facts([[_('Role'), managedRole], [_('Network version'), data.version], [_('Management interface'), data.local.management ? data.local.management.device : _('Unavailable')], [_('Management addresses'), data.local.management ? data.local.management.addresses.map(function(a) { return a.address; }).join(', ') : _('Unavailable')], [_('Background services'), widgets.background(data)]])]));
		if (data.intent && (!controller || controller.role === 'unbound')) result.push(widgets.section(_('Management'), [button(_('Exit management'), function() {
			widgets.modal(_('Restore original managed settings'), [E('p', {}, _('Only unchanged managed fields will be restored. External edits must be resolved first.')),
				E('div', { 'class': 'mm-actions' }, [button(_('Cancel'), function() { ui.hideModal(); }), button(_('Preview restoration'), function() {
					return call('release', requestId(), true).then(function() { ui.hideModal(); return refresh(); }).catch(notify);
				}, !writable)])]);
		}, !writable)]));
	}
	if (page === 'nodes' && (!data.cluster || data.cluster.identity.role === 'unbound')) {
		var identity=data.cluster && data.cluster.identity, overrides=identity && identity.overrides || {};
		var facts=[
			[_('Node'), data.intent ? data.intent.name : data.local.board ? data.local.board.hostname : _('Local node')],
			[_('Model'), data.local.board ? data.local.board.model : _('Unavailable')],
			[_('Role'), identity && identity.role!=='unbound' ? identity.role==='root' ? identity.gateway==='bridge' ? _('Root bridge') : _('Root router') : _('AP node') : role(data.intent)],
			[_('Management addresses'),data.local.management ? data.local.management.addresses.map(function(a) { return a.address; }).join(', ') : _('Unavailable')],
			[_('Mesh intent version'), data.cluster ? data.cluster.version : _('Unavailable')],
			[_('Local transaction version'), data.version]
		];
		facts.push([_('Configuration'),widgets.status(data.drift.length ? _('Managed differences: %s').format(data.drift.length) : _('Consistent'),data.drift.length ? 'warning' : 'good')]);
		if(identity && identity.role==='ap')facts.push([_('AP uplink port'),overrides.uplink || _('Unavailable')]);
		result.push(widgets.section(_('This device'),[widgets.facts(facts)]));
	}
	if (page === 'wireless') result.push(widgets.section(_('Local radios'), [
		E('div', { 'class': 'mm-radio-rows' }, cap.radios.map(function(r) {
			var assigned = data.intent && data.intent.wifi.enabled && data.intent.wifi.radios.indexOf(r.name) >= 0;
			return E('div', { 'class': 'mm-radio-row' }, [
				E('strong', {}, [r.name]), E('span', { 'class': 'mm-radio-meta' }, [
					_('Channel') + ' ' + text(r.channel), ' · ', _('Country') + ' ' + text(r.country)
				]), widgets.status(assigned ? data.intent.wifi.ssid : _('Not managed'), assigned ? 'good' : 'neutral')
			]);
		}))
	]));
	if (page === 'wireless' && data.local.roaming) {
		var roaming = data.local.roaming;
		var roamingLabel = !roaming.installed ? _('usteer is not installed') : roaming.running == null ? _('Unavailable') :
			!roaming.managed ? roaming.running ? _('Running outside Mesh management') : _('Not managed') :
			!roaming.healthy ? _('Steering configuration is not effective') : roaming.requested ? _('Enabled') : _('Disabled');
		result.push(widgets.section(_('Roaming assistance'), [
			widgets.facts([[_('Status'), widgets.status(roamingLabel, roaming.managed && !roaming.healthy ? 'warning' : roaming.healthy ? 'good' : 'neutral')]]),
			widgets.details(_('Backend details'), [widgets.facts([
				[_('Backend'), 'usteer ' + (roaming.version || _('Unknown'))],
				[_('Communication interfaces'), (roaming.interfaces || []).join(', ') || '-'],
				[_('Policy support'), roaming.supported ? _('Supported') : _('Unsupported')]
			])])
		]));
	}
	if (page === 'backhaul') {
		var identity = data.cluster && data.cluster.identity;
		var active = data.local.backhaul;
		var mode = data.intent && data.intent.backhaul && data.intent.backhaul.mode ||
			data.cluster && data.cluster.intent && data.cluster.intent.backhaul && data.cluster.intent.backhaul.mode;
		if(!identity || identity.role==='unbound')result.push(widgets.section(_('Backhaul'),[
			E('p',{'class':'mm-empty-state'},[_('Not enrolled')])
		]));
		if (identity && identity.role === 'ap') {
			var backhaulFacts = [
				[_('Backhaul mode'), backhaulModeLabel(mode)],
				[_('Active path'), widgets.status(active ? pathLabel(active.active) : _('Unavailable'), active && active.active !== 'none' ? 'good' : 'warning')],
				[_('AP uplink port'), identity.overrides && identity.overrides.uplink || _('Unavailable')],
				[_('Wired path'), widgets.status(active && active.wired ? _('Verified') : active && active.carrier ? _('Not verified') : _('Link down'), active && active.wired ? 'good' : 'warning')]
			];
			if (data.intent && data.intent.backhaul.mode !== 'wired') backhaulFacts.push(
				[_('Wireless path'), widgets.status(active && active.wireless ? _('Verified') : _('Not verified'), active && active.wireless ? 'good' : 'warning')]);
			if (active && active.quality) backhaulFacts.push(
				[_('Mesh signal'), active.quality.signal_dbm + ' dBm'],
				[_('Reported PHY rate'), active.quality.phy_rate_mbps + ' Mb/s'],
				[_('Mesh channel'), active.quality.channel]
			);
			result.push(widgets.section(_('Current backhaul'), [widgets.facts(backhaulFacts)]));
		}
		if (identity && identity.role === 'root') {
			var members = (data.cluster.members || []).filter(function(node) { return node.authorized; });
			result.push(widgets.section(_('AP backhaul'), [
				widgets.facts([[_('Backhaul mode'), backhaulModeLabel(mode)]], true), table([
				_('AP node'), _('Active path'), _('Wired path'), _('Wireless path'),
				_('Mesh signal'), _('Reported PHY rate')
			], members.map(function(node) {
				var backhaul = node.online && node.report && node.report.backhaul;
				var quality = backhaul && backhaul.quality;
				return [node.name || node.id,
					widgets.status(backhaul ? pathLabel(backhaul.active) : _('Offline'),
						backhaul && backhaul.active !== 'none' ? 'good' : 'warning'),
					widgets.status(!backhaul ? _('Unavailable') : backhaul.wired ? _('Verified') :
						backhaul.carrier ? _('Not verified') : _('Link down'), backhaul && backhaul.wired ? 'good' : 'neutral'),
					widgets.status(mode === 'wired' ? _('Not enabled') : !backhaul ? _('Unavailable') :
						backhaul.wireless ? _('Verified') : _('Not verified'),
						mode !== 'wired' && backhaul && backhaul.wireless ? 'good' : 'neutral'),
					quality ? quality.signal_dbm + ' dBm' : _('Unavailable'),
					quality ? quality.phy_rate_mbps + ' Mb/s' : _('Unavailable')];
			}), _('No AP nodes joined'))]));
		}
	}
	if (page === 'clients') result.push(clientView.render(data));
	if (page === 'history') {
		result.push(history.section('local-history', 'local', _('Local changes'), [
			_('Time'), _('Status'), _('Local transaction version'), _('Transaction'), _('Details')
		], function(h) {
			var conflicts = (h.conflicts || []).map(function(c) { return c.path; }).join(', ');
			return [h.timestamp ? new Date(h.timestamp*1000).toLocaleString() : '-',
				widgets.status(stateLabel(h.status),h.status === 'committed' ? 'good' : h.status === 'rollback_conflict' ? 'error' : 'warning'),
				h.version,E('code', {title:h.id}, [h.id]),
				widgets.failure(conflicts ? 'rollback_conflict: ' + conflicts : h.failure, 'local:' + h.id) || (h.kind === 'overrides' ? _('Local settings') : '-')];
		}, _('No local changes yet'), {writable:writable, refresh:refresh}));
		if (data.active && data.active.status === 'rollback_conflict') result.push(widgets.section(_('Recovery conflict'), [table([_('Setting'), _('Details')], data.active.conflicts.map(function(c) { return [c.path, c.message]; }))]));
	}
	if (page === 'diagnostics') {
		var identity = data.cluster && data.cluster.identity;
		var download = button(_('Download redacted diagnostics'), function() {
			return call('diagnostics').then(function(report) {
				var url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
				var a = E('a', { href: url, download: 'mesh-manager-diagnostics.json' }); document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
			}).catch(notify);
		});
		result.push(widgets.section(_('Dependency checks'), [table([_('Dependency'), _('Status')], [
			['ubus', cap.bus], ['dnsmasq', cap.dnsmasq], ['firewall4', cap.firewall],
			['hostapd/wpad', cap.hostapd], ['SAE', cap.sae], [_('Background services'), widgets.background(data)]
		].map(function(row) {
			if (typeof row[1] === 'object') return row;
			return [row[0], widgets.status(row[1] ? _('Available') : _('Unavailable'), row[1] ? 'good' : 'error')];
		}))], [download]));
		if (data.local.lan_services) {
			var services = data.local.lan_services;
			var serviceNames = {lan_dhcp_configuration:_('LAN DHCP configuration'),lan_dhcp_service:_('LAN DHCP service'),lan_ipv6_service:_('LAN IPv6 service')};
			var serviceStates = {ready:_('Ready'),not_running:_('Not running'),not_required:_('Not required'),invalid_configuration:_('Configuration needs attention'),unavailable:_('Unavailable')};
			result.push(widgets.section(_('LAN services'), [table([_('Check'),_('Status')], (services.checks || []).map(function(check) {
				return [serviceNames[check.name] || _('Unknown'), widgets.status(serviceStates[check.status] || _('Unknown'),
					check.status === 'ready' ? 'good' : check.status === 'not_required' ? 'neutral' : 'warning')];
			})), E('p', {'class':'mm-muted'}, [_('Checks local configuration and service processes. An AP with DHCP and IPv6 announcements disabled does not need these servers. This does not test client connectivity.')]),
				E('span', {'class':'mm-muted'}, [_('Updated at %s').format(services.observed_at ? new Date(services.observed_at * 1000).toLocaleTimeString() : _('Unavailable'))])
			]));
		}
		if (data.local.certificates) {
			var certificates = data.local.certificates;
			var certificateStates = {valid:_('Valid'),expiring:_('Expires within 30 days'),expired:_('Expired'),
				not_yet_valid:_('Not yet valid'),invalid:_('Invalid certificate'),identity_mismatch:_('Certificate identity mismatch'),
				untrusted:_('Certificate chain not trusted'),clock_invalid:_('Check device time'),missing:_('Certificate missing'),
				unavailable:_('Unavailable'),not_enrolled:_('Not enrolled')};
			result.push(widgets.section(_('Certificates'), [table([_('Certificate'),_('Status'),_('Expires')],
				[['device',_('Device certificate')],['ca',_('Network CA')]].map(function(row) {
					var value = certificates[row[0]] || {};
					return [row[1],widgets.status(certificateStates[value.status] || _('Unknown'),
						value.status === 'valid' ? 'good' : value.status === 'not_enrolled' ? 'neutral' : 'warning'),
						value.expires_at ? new Date(value.expires_at * 1000).toLocaleDateString() : '-'];
				})), E('p', {'class':'mm-muted'}, [_('Checks local certificates against the saved identity and device time. This does not check private keys, controller connectivity or remote revocation. Certificate renewal is not yet available.')])
			]));
		}
		result.push(widgets.section(_('DFS and channels'), [table([_('Radio'), _('Channel'), _('Status')], (data.local.dfs || []).map(function(radio) {
			var label = radio.cac_active === true ? _('CAC in progress (%s s)').format(radio.cac_seconds_left == null ? '?' : radio.cac_seconds_left) :
				radio.cac_active === false ? _('No CAC in progress') : _('Unavailable');
			return [radio.radio, radio.channel || '-', widgets.status(label, radio.cac_active === true ? 'warning' : 'neutral')];
		}), _('DFS status unavailable'))]));
		var localSoftware = data.local.software || {};
		var firmwareRows = [{name:_('This device'),software:localSoftware,local:true}];
		if (identity && identity.role === 'root') (data.cluster.members || []).filter(function(node) {
			return node.authorized;
		}).forEach(function(node) {
			firmwareRows.push({name:node.name || node.id,software:node.report && node.report.software || {},online:node.online});
		});
		result.push(widgets.section(_('Firmware versions'), [widgets.details(_('Compare node firmware'), [
			table([_('Node'),_('Firmware'),_('Target platform'),_('Kernel'),_('Status')],firmwareRows.map(function(node) {
				var software=node.software;
				var comparable=['distribution','version','revision'].every(function(field) {return software[field] && localSoftware[field];});
				var differs=comparable && ['distribution','version','revision'].some(function(field) {return software[field] !== localSoftware[field];});
				var state=node.local ? _('Local observation') : !node.online ? _('Last reported (offline)') :
					!comparable ? _('Version unavailable') : differs ? _('Different firmware') : _('Same firmware version');
				return [node.name,E('span',{},[software.version ? (software.distribution || '')+' '+software.version : _('Unavailable'),
					E('small',{'class':'mm-muted'},[software.revision || '-'])]),software.target || '-',software.kernel || '-',
					widgets.status(state, !node.local && node.online && differs ? 'warning' : 'neutral')];
			})),E('p',{'class':'mm-muted'},[_('Different firmware may support different features. Matching versions do not prove compatibility; configuration preflight still checks actual device capabilities. Offline values are the last report.')])
		]) ]));
		result.push(diagnostics.active(data,writable));
		result.push(diagnostics.packages());
		result.push(diagnostics.logs(writable));
		if(identity && identity.role!=='unbound')result.push(widgets.section(_('Technical details'), [widgets.details(_('Device identities'), [
			table([_('Identity'), _('Details')], [
				[_('Device identity'), E('span', {}, [identity.id || '-'])],
				[_('Controller identity'), E('span', {}, [identity.controller_id || '-'])],
				[_('Network identity'), E('span', {}, [identity.network_id || '-'])]
			])
		])]));
	}
	return result;
}

return baseclass.extend({
	page: function(page) {
		return {
			load: function() { return loadStatus(page, 0); },
			render: function(data) {
				var writable = L.hasViewPermission(), panel = E('div'), error = E('div'), forms = E('div'), formKey = null;
				var title = document.getElementById('mesh-manager-title') || E('h2', { id: 'mesh-manager-title', 'class': 'mm-app-title' }, [_('Mesh Manager')]);
				var description = document.getElementById('mesh-manager-description') || E('p', { id: 'mesh-manager-description', 'class': 'mm-app-description' }, [_('Built on native OpenWrt components to manage Mesh nodes and Wi-Fi, with 802.11k/v/r client roaming.')]);
				var tabs = document.querySelector('#tabmenu');
				if(tabs) {
					tabs.parentNode.insertBefore(title,tabs);
					tabs.parentNode.insertBefore(description,tabs);
				}
				function expanded(root) {
					var values={};
					root.querySelectorAll('details[data-mm-detail]').forEach(function(detail) { values[detail.dataset.mmDetail]=detail.open; });
					return values;
				}
				function restoreExpanded(root,values) {
					root.querySelectorAll('details[data-mm-detail]').forEach(function(detail) {
						if(detail.dataset.mmDetail in values)detail.open=values[detail.dataset.mmDetail];
					});
				}
				function renderStatus(next) {
					var panelDetails=expanded(panel);
					dom.content(panel, content(page, next, refresh, writable)); restoreExpanded(panel,panelDetails); dom.content(error, []);
					var identity = next.cluster && next.cluster.identity, key = identity ? identity.role + ':' + (identity.network_id || '') + ':' +
						(identity.joining && identity.joining.status || '') + ':' + !!next.configured + ':' + !!next.mesh_enabled : 'legacy';
					if (key !== formKey) {
						var formDetails=expanded(forms);
						var managed = identity && identity.role !== 'unbound';
						dom.content(forms, [cluster.forms(page, next, refresh, writable), !managed && !identity && (page === 'overview' || page === 'wireless') ? wizard(next, refresh, writable) : E('div')]);
						restoreExpanded(forms,formDetails);
						formKey = key;
					}
					if(forms.firstElementChild && forms.firstElementChild.mmUpdate)forms.firstElementChild.mmUpdate(next);
				}
				function refresh(resetForms) {
					if(resetForms===true)formKey=null;
					return loadStatus(page, 0).then(function(next) { renderStatus(next);return next; }).catch(function(e) {
						dom.content(error,E('p',{'class':'alert-message warning'},[_('Status update failed: %s').format(e.message)]));
					});
				}
				renderStatus(data);
				poll.add(refresh, 3);
				return E('div', { 'class': 'mm-page', 'data-mm-view': page, 'aria-label': _('Mesh Manager') }, [
					E('link', { rel: 'stylesheet', href: L.resource('mesh_manager/mesh-manager.css')+'?v=20261015-guest-1' }),
					tabs ? E('span') : title,
					tabs ? E('span') : description,
					error, panel, forms
				]);
			},
			handleSave: null, handleSaveApply: null, handleReset: null
		};
	}
});
