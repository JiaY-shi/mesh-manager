// SPDX-License-Identifier: GPL-2.0-only
'use strict';
'require baseclass';
'require ui';

function modal(title, children, preview) {
	return ui.showModal(title, [E('div', { 'class': 'mm-dialog' }, children)], 'mm-modal', preview ? 'mm-modal-preview' : 'mm-modal-small');
}

function help(description) {
	return E('span', { 'class': 'cbi-value-description mm-help', tabindex: 0,
		'data-tooltip': description, 'aria-label': description,
		click: function(ev) { ev.currentTarget.focus(); } }, [E('span', { hidden: '' }, [description])]);
}

var fieldId = 0;
function field(label, input, description) {
	var id = 'mm-field-' + (++fieldId), control = input.matches('input, select, textarea') ? input : null;
	if (control) control.id = id;
	return E('div', { 'class': 'cbi-value mm-field' }, [
		E('div', { 'class': 'mm-field-label' }, [
			E('label', { 'class': 'cbi-value-title', 'for': control ? id : null }, [label]),
			description ? help(description) : E('span')
		]), E('div', { 'class': 'cbi-value-field' }, [input])
	]);
}
function lockEditor(editor, locked) {
	if (!!editor.mmLocked === !!locked) return;
	editor.mmLocked = !!locked;
	editor.setAttribute('aria-disabled', String(!!locked));
	editor.querySelectorAll('input, select, textarea').forEach(function(control) {
		if (locked) { control.mmDisabled = control.disabled; control.disabled = true; }
		else control.disabled = !!control.mmDisabled;
	});
}

function text(value) {
	return value == null ? '-' : typeof value === 'object' ? JSON.stringify(value) : String(value);
}

function content(value) {
	return value instanceof Node ? value : text(value);
}

function setting(item) {
	var names={ssid:_('SSID'),key:_('Passphrase'),encryption:_('Encryption'),ipaddr:_('IPv4 address'),netmask:_('Netmask'),gateway:_('Bridge gateway override'),mesh_id:_('Mesh ID')};
	var label=item.option==='disabled' && item.config==='wireless' ? _('Wireless interface state') : names[item.option] || _('Managed setting');
	var path=item.config+'.'+item.section+(item.option ? '.'+item.option : '');
	return E('span',{'class':'mm-setting',title:path},[label,E('small',{},[item.section])]);
}

function status(label, kind) {
	return E('span', { 'class': 'mm-status mm-status-' + (kind || 'neutral') }, [
		E('span', { 'class': 'mm-status-mark', 'aria-hidden': 'true' }), label
	]);
}

function facts(rows, compact) {
	return E('dl', { 'class': 'mm-facts' + (compact ? ' mm-facts-compact' : '') }, rows.map(function(row) {
		return E('div', { 'class': 'mm-fact' }, [
			E('dt', {}, [row[0]]), E('dd', {}, [content(row[1])])
		]);
	}));
}

function section(title, children, actions) {
	return E('section', { 'class': 'mm-section' }, [
		E('div', { 'class': 'mm-section-heading' }, [
			E('h3', {}, [title]), actions ? E('div', { 'class': 'mm-actions' }, actions) : E('span')
		]), E('div', { 'class': 'mm-section-content' }, children)
	]);
}

function details(title, children, open) {
	return E('details', { 'class': 'mm-details', 'data-mm-detail': title, open: open ? '' : null }, [
		E('summary', {}, [title]), E('div', { 'class': 'mm-details-body' }, children)
	]);
}

function table(headers, rows, empty) {
	if (!rows.length)
		return E('p', { 'class': 'mm-empty-state' }, [empty || _('No data')]);
	var body = rows.map(function(row) {
		return E('tr', { 'class': 'tr' }, row.map(function(cell, index) {
			return E('td', { 'class': 'td', 'data-label': headers[index] }, [content(cell)]);
		}));
	});
	return E('div', { 'class': 'mm-table-wrap' }, [
		E('table', { 'class': 'table mm-table' }, [
			E('tr', { 'class': 'tr table-titles' }, headers.map(function(header) {
				return E('th', { 'class': 'th' }, [header]);
			}))
		].concat(body))
	]);
}

var tablePages = Object.create(null);
function pagedTable(key, headers, items, renderRow, empty) {
	var size = 5, pages = Math.max(1, Math.ceil(items.length / size));
	var current = Math.min(tablePages[key] || 0, pages - 1);
	var root = E('div', { 'class': 'mm-paged-table', 'data-mm-pager': key });
	function render() {
		tablePages[key] = current;
		root.dataset.mmPage = current;
		root.replaceChildren(table(headers, items.slice(current * size, (current + 1) * size).map(renderRow), empty));
		if (pages < 2) return;
		function navigation(label, symbol, target, disabled) {
			return E('button', { 'class': 'cbi-button cbi-button-neutral mm-page-button', type: 'button',
				disabled: disabled || null, 'aria-label': label, 'data-tooltip': label,
				click: function() { current = target; render(); } }, [symbol]);
		}
		root.appendChild(E('div', { 'class': 'mm-pagination', 'aria-label': _('Pagination') }, [
			E('span', { 'class': 'mm-pagination-count' }, [
				_('Records %s-%s of %s').format(current * size + 1, Math.min((current + 1) * size, items.length), items.length)
			]),
			navigation(_('Previous page'), '\u2039', current - 1, current === 0),
			E('span', { 'class': 'mm-pagination-page', 'aria-live': 'polite' }, [_('Page %s of %s').format(current + 1, pages)]),
			navigation(_('Next page'), '\u203a', current + 1, current === pages - 1)
		]));
	}
	render();
	return root;
}

function records(rows, empty) {
	if (!rows.length)
		return E('p', { 'class': 'mm-empty-state' }, [empty || _('No data')]);
	return E('ol', { 'class': 'mm-records' }, rows.map(function(row) {
		return E('li', { 'class': 'mm-record' }, [
			E('div', { 'class': 'mm-record-primary' }, [content(row[0]), content(row[1])]),
			E('div', { 'class': 'mm-record-meta' }, [content(row[2])]),
			row[3] ? E('div', { 'class': 'mm-record-detail' }, [content(row[3])]) : E('span')
		]);
	}));
}

function configurationError(error) {
	var code = error && error.code, section = error && error.section;
	if (code === 'handoff_conflict' || code === 'storage_conflict') return _('Settings changed during first configuration. Existing values and joining credentials were preserved. Check node changes before retrying.');
	if (code === 'handoff_paused' || code === 'handoff_recovery') return _('First configuration requires recovery or review. Mesh will not restart the temporary connection automatically. Check change records.');
	if (code === 'handoff_unhealthy' || code === 'handoff_timeout') return _('Waiting for Root to confirm the first configuration over the managed connection. Joining credentials are retained; retrying automatically.');
	if (code === 'control_required') return _('Root requires the isolated management connection for this operation. Check the control path, then retry.');
	if (code === 'invalid_transport') return _('The management listener could not be verified. Update Root and AP together and check the service status.');
	if (code === 'control_protocol_unsupported') return _('The AP has not reported support for controller-assigned addresses. Wait for its next report; if this persists, update Root and AP together before retrying.');
	if (code === 'control_address_invalid' || code === 'control_address_conflict') return _('Control address records conflict or are invalid. Configuration changes are blocked; keep the current settings and export diagnostics for investigation.');
	if (code === 'control_unavailable') return _('The isolated controller connection is unavailable. Restore the connection and retry confirmation, or roll back. Unconfirmed changes roll back automatically at the deadline.');
	if (code === 'wired_no_address') return _('The wired interface has not obtained an IPv4 address. Check the cable and DHCP service; retrying in 30 seconds.');
	if (code === 'peer_unavailable') return _('The controller connection failed. Check the network link, device time and controller status, then try again.');
	if (code === 'clock_error') return _('Device time could not be synchronized. Check Root time and update Mesh management on Root and AP, then retry.');
	if (code === 'signature_error') return _('Controller response verification failed. Check device time and update Root and AP together.');
	if (code === 'response_too_large') return _('The signed configuration exceeds the transmission limit. Reduce the configuration and preview again.');
	if (code === 'busy') return _('Manager is busy; retry later.');
	if (code === 'ap_restore_required') return _('Disable Mesh on every AP and restore its original settings before disabling Root or revoking its identity.');
	if (code === 'ap_restore_unverified') return _('AP restoration has not been verified. Keep Root enabled and reconnect the AP to complete restoration.');
	if (code === 'root_restore_unverified') return _('Mesh restoration could not be verified. Check the actual network and change records; external configuration was preserved.');
	if (code === 'node_offline') return _('The AP has not provided a fresh verified report. Reconnect it and retry after its status updates.');
	if (code === 'steering_dependency') return _('Install official usteer and stop other steering services before enabling assistance.');
	if (code === 'steering_unsupported') return _('This usteer version does not support the required advisory policy.');
	if (code === 'steering_boot_disabled') return _('Enable usteer in System → Startup before enabling roaming assistance.');
	if (code === 'steering_roaming_required') return _('Enable Wi-Fi and 802.11k/v before enabling roaming assistance.');
	if (code === 'steering_conflict') return _('Keep exactly one usteer configuration section before enabling assistance.');
	if (code === 'wireless_probe_unavailable')
		return _('Wireless capability checks did not complete. Retry the preview when the device is less busy.');
	if (code === 'radio_capability_unknown')
		return _('The selected radio capabilities could not be verified. Retry the preview before applying.');
	if (code === 'radio_width_unsupported')
		return _('The selected radio does not support the requested backhaul width. Choose a width supported by every node.');
	if (code === 'wireless_control_incompatible')
		return _('The installed Wi-Fi components incorrectly reject interface activation. Update or repair the firmware components before joining; extending the timeout will not help.');
	if (code === 'controller_address_unsupported')
		return _('Coordinated controller address migration is not implemented; preserve the existing static LAN address');
	if (code === 'uplink_shared')
		return _('The selected AP uplink is also used by another network (%s). Adjust that network before enabling Mesh.').format(section || '-');
	if (code === 'uplink_topology_unknown')
		return _('The device ownership of another network (%s) cannot be verified. Inspect its configuration before enabling Mesh.').format(section || '-');
	return error && error.message || _('Change failed; inspect technical details.');
}

function failure(message, key) {
	if (!message) return null;
	var known = [
		[/^(handoff_conflict|storage_conflict)(:|$)/, _('Settings changed during first configuration. Existing values and joining credentials were preserved. Check node changes before retrying.')],
		[/^handoff_(paused|recovery)(:|$)/, _('First configuration requires recovery or review. Mesh will not restart the temporary connection automatically. Check change records.')],
		[/^handoff_(unhealthy|timeout)(:|$)/, _('Waiting for Root to confirm the first configuration over the managed connection. Joining credentials are retained; retrying automatically.')],
		[/^control_required:/, _('Root requires the isolated management connection for this operation. Check the control path, then retry.')],
		[/^invalid_transport:/, _('The management listener could not be verified. Update Root and AP together and check the service status.')],
		[/^control_protocol_unsupported:/, _('The AP has not reported support for controller-assigned addresses. Wait for its next report; if this persists, update Root and AP together before retrying.')],
		[/^control_address_(invalid|conflict):/, _('Control address records conflict or are invalid. Configuration changes are blocked; keep the current settings and export diagnostics for investigation.')],
		[/^control_unavailable:/, _('The isolated controller connection is unavailable. Restore the connection and retry confirmation, or roll back. Unconfirmed changes roll back automatically at the deadline.')],
		[/^wired_no_address(:|$)/, _('The wired interface has not obtained an IPv4 address. Check the cable and DHCP service; retrying in 30 seconds.')],
		[/^peer_unavailable:/, _('The controller connection failed. Check the network link, device time and controller status, then try again.')],
		[/^clock_error(:|$)/, _('Device time could not be synchronized. Check Root time and update Mesh management on Root and AP, then retry.')],
		[/^signature_error:/, _('Controller response verification failed. Check device time and update Root and AP together.')],
		[/^response_too_large:/, _('The signed configuration exceeds the transmission limit. Reduce the configuration and preview again.')],
		[/^local_recovery/, _('The node performed local recovery. Check its transaction history.')],
		[/^Confirmation timed out/, _('Health confirmation timed out; the previous configuration was restored. Inspect the failed health checks.')],
		[/^Device rebooted before confirmation/, _('The device rebooted before confirmation; the previous configuration was restored.')],
		[/^controller_address_unsupported/, _('Coordinated controller address migration is not implemented; preserve the existing static LAN address')],
		[/^uplink_shared/, _('The selected AP uplink is also used by another network. Adjust that network before enabling Mesh.')],
		[/^uplink_topology_unknown/, _('The AP uplink topology cannot be verified. Inspect other network configurations before enabling Mesh.')],
		[/^restore_dhcp_conflict/, _('Restoring DHCP on the connected uplink is unsafe. Disconnect that cable or move it to the original WAN port, then preview again.')],
		[/^restore_(link_unknown|topology_unknown)/, _('The original network or uplink state cannot be verified. Check the wiring and network configuration, then preview again.')],
		[/^AP Mesh operation failed/, _('AP Mesh operation failed; Root remains enabled.')],
		[/^busy:/, _('Manager is busy; retry later.')],
		[/^ap_restore_required(:|$)/, _('Disable Mesh on every AP and restore its original settings before disabling Root or revoking its identity.')],
		[/^ap_restore_unverified(:|$)/, _('AP restoration has not been verified. Keep Root enabled and reconnect the AP to complete restoration.')],
		[/^(root_restore_unverified(:|$)|Root restoration journal changed|Committed Root restoration cannot be verified)/, _('Mesh restoration could not be verified. Check the actual network and change records; external configuration was preserved.')],
		[/^rollback_conflict:/, _('External change preserved; manual recovery required')],
		[/^Controller candidate could not be applied or confirmed/, _('Controller did not confirm the change; nodes rolled back.')],
		[/^Controller restarted or cluster deadline expired/, _('Controller restarted or timed out; check each node rollback.')],
		[/^Cancellation preserved committed batches/, _('Cancelled. Some nodes had already committed; apply a new change to make the network consistent.')],
		[/^Rollback requires review/, _('Recovery finished with conflicts or failures; check each node before making another change.')],
		[/^Unconfirmed change timed out or device rebooted/, _('Unconfirmed change was rolled back after timeout or reboot.')]
	];
	var summary = _('Change failed; inspect technical details.');
	for (var i = 0; i < known.length; i++) {
		if (known[i][0].test(message)) { summary = known[i][1]; break; }
	}
	return E('details', { 'class': 'mm-failure', 'data-mm-detail': key ? 'failure:' + key : null }, [
		E('summary', {}, [summary]), E('code', {}, [message])
	]);
}

function checkList(rows) {
	return E('ul', { 'class': 'mm-check-list' }, rows.map(function(row) {
		return E('li', {}, [E('span', {}, [row[0]]), status(row[1], row[2])]);
	}));
}

return baseclass.extend({
	recoveryReady: function(cap) { cap=cap && cap.capabilities || cap || {}; return cap.daemon===true || cap.daemon_on_demand===true; },
	background: function(data) {
		var cap=data.capabilities || {},mode=cap.background;
		if(mode==='stopped')return status(_('Stopped; starts when needed'),'neutral');
		if(mode==='stopping')return status(_('Stopping background services'),'neutral');
		if(mode==='adjusting')return status(_('Updating background services'),'neutral');
		if(mode==='unknown')return status(_('Unavailable'),'warning');
		if(mode==='standby')return status(_('Standby for remote management'),'neutral');
		if(mode==='recovery')return status(_('Recovery in progress'),'warning');
		return status(cap.daemon ? _('Running') : _('Unavailable'),cap.daemon ? 'good' : 'error');
	},
	text: text,
	status: status,
	facts: facts,
	section: section,
	details: details,
	table: table,
	pagedTable: pagedTable,
	records: records,
	failure: failure,
	configurationError: configurationError,
	checkList: checkList,
	help: help,
	field: field,
	modal: modal,
	setting: setting,
	lockEditor: lockEditor
});
