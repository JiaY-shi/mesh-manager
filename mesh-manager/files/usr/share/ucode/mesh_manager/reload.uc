// SPDX-License-Identifier: GPL-2.0-only
'use strict';

export const HEALTH_MARGIN_SECONDS = 10;

export function execute(ops, io, confirmation_deadline) {
	let changed = {};
	for (let op in ops) changed[op.config] = true;
	if (!length(keys(changed))) return;
	let deadline = io.now() + 60;
	if (confirmation_deadline != null) {
		if (type(confirmation_deadline) != 'int' && type(confirmation_deadline) != 'double')
			die('reload_error: Confirmation budget exhausted');
		deadline = min(deadline, confirmation_deadline - HEALTH_MARGIN_SECONDS);
	}
	function remaining() { return int((deadline - io.now()) * 1000); }
	function exhausted() {
		die(confirmation_deadline != null ? 'reload_error: Confirmation budget exhausted' : 'reload_error: Reload budget exhausted');
	}
	if (remaining() <= 0) exhausted();
	if (changed.network || changed.wireless) {
		let seconds = min(10, int(remaining() / 1000));
		if (seconds <= 0) exhausted();
		io.network(seconds);
		if (io.now() > deadline) exhausted();
	}
	for (let service, needed in {
		dnsmasq: changed.network || changed.dhcp,
		odhcpd: changed.network || changed.dhcp,
		firewall: changed.network || changed.firewall,
		usteer: changed.usteer
	}) {
		if (!needed || !io.available(service)) continue;
		let timeout = remaining();
		if (timeout <= 0) exhausted();
		// dnsmasq reload starts the procd instance and immediately sends HUP.
		// A newly spawned jail may still have the default signal disposition.
		// Config/network changes require a fresh instance; do not signal it early.
		if (!io.service(service, min(15000, timeout), service == 'dnsmasq' ? 'restart' : 'reload'))
			die('reload_error: Cannot reload ' + service);
		if (io.now() > deadline) exhausted();
	}
	if (io.now() > deadline) exhausted();
}
