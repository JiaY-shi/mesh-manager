// SPDX-License-Identifier: GPL-2.0-only
'use strict';

// Check only services required by the actual LAN configuration. An AP with
// DHCP/RA disabled does not need a local server. Missing observations fail closed.
export function lan_service_health(snapshot, observe) {
	let dhcp = snapshot.dhcp || {}, checks = [],
		lan = filter(values(dhcp), s => s.type == 'dhcp' && s.values.interface == 'lan');
	if (length(lan) != 1) return [{name:'lan_dhcp_configuration',ok:false}];
	let options = lan[0].values,
		ignored = index(['1','yes','true','on'], options.ignore) >= 0;
	if (!ignored) {
		let candidates = filter(keys(dhcp), name => dhcp[name].type == 'dnsmasq'),
			name = options.instance;
		if (name == null || name == '') name = length(candidates) == 1 ? candidates[0] : null;
		let valid = type(name) == 'string' && index(candidates,name) >= 0 &&
			index(['1','yes','true','on'],dhcp[name].values.disabled) < 0;
		push(checks,{name:'lan_dhcp_configuration',ok:valid});
		if (valid) {
			let observed = observe('dnsmasq');
			push(checks,{name:'lan_dhcp_service',ok:observed?.dnsmasq?.instances?.[name]?.running === true});
		}
	}
	if (length(filter(['ra','dhcpv6','ndp'], key =>
		index(['server','relay','hybrid'],options[key]) >= 0))) {
		let observed = observe('odhcpd'), instances = observed?.odhcpd?.instances;
		push(checks,{name:'lan_ipv6_service',ok:type(instances) == 'object' &&
			length(filter(values(instances), i => i.running === true)) > 0});
	}
	return checks;
}

// Observational only: this richer result never authorizes a transaction.
export function lan_service_diagnostics(snapshot, observe, wall) {
	let observations = {}, checks = lan_service_health(snapshot, name => {
		try { observations[name] = observe(name); }
		catch (e) { observations[name] = null; }
		return observations[name];
	}), configuration = filter(checks, c => c.name == 'lan_dhcp_configuration')[0];
	return { observed_at: type(wall) == 'int' ? wall : null,
		checks: map(['lan_dhcp_configuration','lan_dhcp_service','lan_ipv6_service'], name => {
			let check = filter(checks, c => c.name == name)[0], status;
			if (name == 'lan_dhcp_configuration') status = configuration?.ok === false ? 'invalid_configuration' : 'ready';
			else if (!check) status = configuration?.ok === false ? 'unavailable' : 'not_required';
			else if (check.ok) status = 'ready';
			else status = type(observations[name == 'lan_dhcp_service' ? 'dnsmasq' : 'odhcpd']) == 'object' ? 'not_running' : 'unavailable';
			return {name,status};
		}) };
}
