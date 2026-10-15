// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import { run } from 'mesh_process';
import { equal } from './model.uc';
import { radio_targets, radio_helper } from './radio_diagnostics.uc';
import { frozen_power_health as readback_health, planning_power_health as live_power_health } from './radio_power_runtime.uc';
import { regulatory_binding, regulatory_phy_binding, regulatory_country } from './regulatory_worker.uc';
import { regulatory_result } from './regulatory_diagnostics.uc';

export function survey_values(text) {
	let result = {}, frequency, active, busy;
	if (type(text) != 'string' || length(text) > 32768) return result;
	function finish() {
		if (frequency != null && type(active) == 'int' && active > 0 && type(busy) == 'int' && busy >= 0 && busy <= active)
			result['' + frequency] = { busy_percent: int(100 * busy / active) };
	}
	for (let line in split(text, '\n')) {
		let match_frequency = match(line, /^[ \t]*frequency:[ \t]+([0-9]+)[ \t]+MHz/);
		if (match_frequency) { finish(); frequency = int(match_frequency[1]); active = busy = null; }
		let match_active = match(line, /^[ \t]*channel active time:[ \t]+([0-9]+)[ \t]+ms/),
			match_busy = match(line, /^[ \t]*channel busy time:[ \t]+([0-9]+)[ \t]+ms/);
		if (match_active) active = int(match_active[1]);
		if (match_busy) busy = int(match_busy[1]);
	}
	finish(); return result;
}

export function planning_observation(snapshot, bus) {
	let netifd, result = {};
	try { netifd = bus?.call('network.wireless', 'status', {}); } catch (e) {}
	let plans = radio_targets({ wireless: snapshot.wireless, netifd }).radios;
	for (let plan in plans) {
		if (!plan.interfaces_complete) continue;
		if (!length(plan.interfaces)) {
			// An idle band still has a kernel WIPHY. Bind the actual libiwinfo
			// mapping and kernel directory twice, then query legal frequencies
			// without creating an interface or transmitting during preview.
			let power=radio_helper(run(['/usr/libexec/mesh-manager-radio-info',plan.radio],'',1000),plan.radio,null),
				binding=regulatory_phy_binding(power.phy,{read:fs.readfile,stat:fs.stat});
			if (!binding) continue;
			let country=snapshot.wireless[plan.radio].values.country || null,
				target={schema:2,radio:plan.radio,phy:binding.phy,phyindex:binding.phyindex,
					configured_country:regulatory_country(country)?country:null,interfaces:[],phy_binding:binding},
				row=regulatory_result(run(['/usr/bin/ucode','/usr/libexec/mesh-manager-radio-regulatory'],sprintf('%J',target),2500),target),
				after=radio_helper(run(['/usr/libexec/mesh-manager-radio-info',plan.radio],'',1000),plan.radio,null);
			if (!equal(binding,regulatory_phy_binding(binding.phy,{read:fs.readfile,stat:fs.stat})) ||
				after.phy!=binding.phy || !equal(power.power,after.power)) continue;
			result[plan.radio]={...row,power:power.power,survey:{}};
			continue;
		}
		let interfaces = [];
		for (let iface in plan.interfaces) {
			let binding = regulatory_binding(iface.ifname, { read: fs.readfile, stat: fs.stat, readlink: fs.readlink });
			if (binding) push(interfaces, { ifname: iface.ifname, binding });
		}
		if (!length(interfaces) || length(interfaces) > 4) continue;
		let binding = interfaces[0].binding, country = snapshot.wireless[plan.radio].values.country || null;
		if (length(filter(interfaces, entry => entry.binding.phy != binding.phy || entry.binding.phyindex != binding.phyindex))) continue;
		let target = { schema: 1, radio: plan.radio, phy: binding.phy, phyindex: binding.phyindex,
			configured_country: regulatory_country(country) ? country : null, interfaces },
			row = regulatory_result(run(['/usr/bin/ucode', '/usr/libexec/mesh-manager-radio-regulatory'], sprintf('%J', target), 2500), target),
			passive = run(['/usr/sbin/iw', 'dev', interfaces[0].ifname, 'survey', 'dump'], '', 1000);
		let power=radio_helper(run(['/usr/libexec/mesh-manager-radio-info',plan.radio,interfaces[0].ifname],'',1000),plan.radio,interfaces[0].ifname);
		result[plan.radio] = { ...row, power:power.phy==binding.phy ? power.power : null,
			survey: passive?.code === 0 ? survey_values(passive.stdout) : {} };
	}
	return result;
}

// Compatibility exports for the finite planning worker and existing callers.
export function frozen_power_health(intent,snapshot,io) { return readback_health(intent,snapshot,io); }
export function planning_power_health(intent,snapshot,bus) { return live_power_health(intent,snapshot,bus); }
