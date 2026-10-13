// SPDX-License-Identifier: GPL-2.0-only
'use strict';
'require baseclass';
'require rpc';
'require ui';
'require mesh_manager.widgets as widgets';

var fetchPage = rpc.declare({ object: 'mesh-manager.sync', method: 'history',
	params: ['group', 'cursor', 'limit', 'fields', 'if_revision'], reject: true });
var clearHistory = rpc.declare({ object: 'mesh-manager.sync', method: 'clear_history',
	params: ['group', 'expected_revision', 'request_id'], reject: true });
var groups = Object.create(null);

function remoteTable(key, group, headers, renderRow, empty, options) {
	options=options || {};
	var labels=options.labels || {};
	var state = groups[key];
	if (!state) state = groups[key] = { root: E('div', { 'class': 'mm-paged-table', 'data-mm-pager': key }),
		page: null, pending: false, error: null, expired: false };
	state.options = options;
	state.headers = headers; state.renderRow = renderRow; state.empty = empty;
	function draw() {
		var opened = {};
		state.root.querySelectorAll('details[data-mm-detail]').forEach(function(node) { opened[node.dataset.mmDetail] = node.open; });
		var page = state.page;
		state.root.dataset.mmPage = page ? Math.floor(page.offset / page.limit) : 0;
		state.root.setAttribute('aria-busy', String(state.pending));
		state.root.replaceChildren(page ? widgets.table(state.headers, page.items.map(state.renderRow), state.empty) :
			E('p', { 'class': 'mm-empty-state' }, [state.error ? (labels.unavailable || _('History is unavailable')) : (labels.loading || _('Loading history…'))]));
		if (state.error) state.root.appendChild(E('div', { 'class': 'mm-pagination', role: 'status' }, [
			E('span', {}, [state.expired ? (labels.expired || _('History changed or expired. Reload from the first page.')) : (labels.failed || _('History update failed. Displayed records may be outdated.'))]),
			E('button', { 'class': 'cbi-button cbi-button-neutral mm-page-button', type: 'button', disabled: state.pending || null,
				click: function() { load('', false); } }, [(labels.reload || _('Reload history'))])
		]));
		if (page && page.total > page.limit) {
			function nav(label, symbol, cursor) {
				return E('button', { 'class': 'cbi-button cbi-button-neutral mm-page-button', type: 'button',
					'aria-label': label, 'data-tooltip': label, disabled: !cursor || state.pending || state.clearing || state.expired || null,
					click: function() { load(cursor, false); } }, [symbol]);
			}
			state.root.appendChild(E('div', { 'class': 'mm-pagination', 'aria-label': _('Pagination') }, [
				E('span', { 'class': 'mm-pagination-count' }, [_('Records %s-%s of %s').format(page.offset + 1,
					Math.min(page.offset + page.limit, page.total), page.total)]),
				nav(_('Previous page'), '\u2039', page.previous_cursor),
				E('span', { 'class': 'mm-pagination-page', 'aria-live': 'polite' }, [_('Page %s of %s').format(
					Math.floor(page.offset / page.limit) + 1, Math.ceil(page.total / page.limit))]),
				nav(_('Next page'), '\u203a', page.next_cursor)
			]));
		}
		state.root.querySelectorAll('details[data-mm-detail]').forEach(function(node) {
			if (node.dataset.mmDetail in opened) node.open = opened[node.dataset.mmDetail];
		});
		if(state.options.changed)state.options.changed(state.page,state.pending,state.error);
	}
	function load(cursor, conditional, restarted) {
		if (state.pending) return;
		state.pending = true; draw();
		return state.loading = (options.fetch || fetchPage)(group, cursor || '', 5, [], conditional && state.page ? state.page.revision : '').then(function(result) {
			if (!result || !result.ok) {
				var error = new Error(result && result.error && result.error.message || 'History unavailable');
				error.code = result && result.error && result.error.code; throw error;
			}
			var page = result.data;
			if (!page || page.group !== group || page.limit !== 5 || !Number.isInteger(page.offset) ||
				!Number.isInteger(page.total) || page.total < 0 || page.total > (options.maximum || 32) ||
				(page.unchanged ? !state.page || state.page.revision !== page.revision || state.page.offset !== page.offset :
					!Array.isArray(page.items) || page.items.length > 5)) throw new Error('Invalid history response');
			if (page.unchanged) page.items = state.page.items;
			state.page = page; state.error = null; state.expired = false;
		}).catch(function(error) {
			// Only the first page refreshes automatically after snapshot expiry.
			// Later pages keep their contents and require an explicit restart.
			if (error.code === 'cursor_expired' && state.page && state.page.offset === 0 && !restarted && conditional) {
				state.pending = false; return load('', false, true);
			}
			state.error = error; state.expired = error.code === 'cursor_expired';
		}).finally(function() { state.pending = false; draw(); });
	}
	state.root.mmReload=function(){return load('',false);};
	state.root.mmCurrent=function(){return state.page;};
	if (!state.pending && !state.expired) load(state.page && state.page.cursor, true);
	return state.root;
}

function historySection(key, group, title, headers, renderRow, empty, options) {
	options = options || {};
	var clear = E('button', { type: 'button', 'class': 'cbi-button cbi-button-neutral',
		'data-mm-clear-history': group, click: confirmClear }, [_('Clear records')]);
	function update() {
		var state = groups[key];
		clear.disabled = !options.writable || !state || state.pending || state.clearing || state.error ||
			!state.page || !state.page.total || !state.page.clear_revision;
	}
	var table = remoteTable(key, group, headers, renderRow, empty, { changed: update });
	function confirmClear() {
		var state = groups[key], page = state.page;
		if (clear.disabled || state.clearing || !page) return;
		var revision = page.clear_revision, bytes = new Uint8Array(16);
		window.crypto.getRandomValues(bytes);
		var request = Array.from(bytes).map(function(value) { return value.toString(16).padStart(2, '0'); }).join('');
		var result = E('p', { role: 'status' });
		var cancel = E('button', { type: 'button', 'class': 'cbi-button cbi-button-neutral',
			click: function() { if (!state.clearing) ui.hideModal(); } }, [_('Cancel')]);
		var confirm = E('button', { type: 'button', 'class': 'cbi-button cbi-button-action', click: function() {
			if (state.clearing) return;
			state.clearing = true; confirm.disabled = true; cancel.disabled = true; update();
			result.textContent = _('Clearing records…');
			return clearHistory(group, revision, request).then(function(reply) {
				if (!reply || !reply.ok) throw Object.assign(new Error(reply && reply.error && reply.error.message || _('Operation failed')),
					{ code: reply && reply.error && reply.error.code });
				ui.addNotification(null, E('p', {}, [_('Cleared %s records.').format(reply.data.cleared)]), 'info');
				ui.hideModal();
				return Promise.resolve(state.loading).then(function() { return table.mmReload(); }).then(function() { if (options.refresh) return options.refresh(); });
			}).catch(function(error) {
				result.textContent = error.code === 'preview_changed' ? _('Records changed. Close this dialog and refresh before clearing.') : widgets.configurationError(error);
			}).finally(function() { state.clearing = false; cancel.disabled = false; update(); });
		} }, [_('Clear records')]);
		widgets.modal(_('Clear records'), [
			E('p', {}, [_('Clear all %s records in “%s”?').format(page.total, title)]),
			E('p', { 'class': 'mm-muted' }, [_('Only this device’s history in this group is cleared. Running operations, Mesh settings and recovery backups are preserved.')]),
			result, E('div', { 'class': 'mm-actions mm-dialog-actions' }, [cancel, confirm])
		]);
	}
	update();
	return widgets.section(title, [table], [clear]);
}

return baseclass.extend({ table: remoteTable, section: historySection });
