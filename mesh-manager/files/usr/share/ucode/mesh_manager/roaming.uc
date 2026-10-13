// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { equal, clone } from './model.uc';

export function steering_policy(roaming) {
	return clone(roaming.policy ?? {scan_rssi:-70,trigger_rssi:-75,signal_difference:8,interval_seconds:60});
}
export function steering_policy_errors(policy) {
	if (policy == null) return [];
	let ranges={scan_rssi:[-90,-40],trigger_rssi:[-90,-40],signal_difference:[3,30],interval_seconds:[30,600]};
	if (type(policy)!='object' || length(keys(policy))!=4 ||
		length(filter(keys(policy),key=>ranges[key]==null))) return ['Invalid custom roaming policy fields'];
	for (let name,range in ranges)
		if (type(policy[name])!='int' || policy[name]<range[0] || policy[name]>range[1])
			return ['Custom roaming thresholds are outside the supported range'];
	return policy.trigger_rssi>policy.scan_rssi-5 ? ['Roaming trigger must be at least 5 dB below the scan threshold'] : [];
}

// Official usteer options only. Keep the policy advisory: no forced disconnect,
// association rejection or per-client overrides hidden outside the managed intent.
export function steering_options(intent) {
	let policy=steering_policy(intent.wifi.roaming);
	return { enabled: intent.wifi.roaming.steering && intent.wifi.enabled ? '1' : '0',
		network: intent.controller ? ['mm_ctl'] : intent.backhaul.mode == 'wired' ? ['mm_cw'] : ['mm_cw', 'mm_cm'],
		ssid_list: [intent.wifi.ssid], local_mode: '0', ipv6: '0', aggressiveness: '1',
		aggressiveness_mac_list: null, node_up_script: null, assoc_steering: '0', load_kick_enabled: '0',
		min_connect_snr: '0', min_snr: '0', initial_connect_delay: '0', band_steering_interval: '0',
		roam_scan_snr: ''+policy.scan_rssi, roam_trigger_snr: ''+policy.trigger_rssi, signal_diff_threshold: ''+policy.signal_difference,
		roam_scan_tries: '3', roam_scan_timeout: '60000', roam_scan_interval: '10000',
		roam_trigger_interval: ''+(policy.interval_seconds*1000), roam_kick_delay: '10000', debug_level: '1' };
}
export function steering_owned(owned) {
	return length(filter(owned || [], op => op.config == 'usteer' && op.option == 'enabled')) > 0;
}
export function steering_service_action(snapshot) {
	let sections=filter(values(snapshot.usteer || {}),section=>section.type=='usteer');
	if(length(sections)!=1)die('configuration_error: Exactly one usteer configuration is required');
	// reload sends set_config to the existing daemon. An unresponsive instance
	// can keep both application and rollback waiting on the same ubus request.
	// Restart the optional advisory service within the existing reload budget;
	// health checks still verify the new instance's effective policy.
	return sections[0].values.enabled=='0' ? 'stop' : 'restart';
}
export function steering_plan(intent, snapshot, cap, owned, resume_managed) {
	let enabled = intent.wifi.roaming.steering, managed = steering_owned(owned), errors = [], ops = [], conflicts = [];
	function fail(code, message) { push(errors, {code, message}); }
	// Mesh release restores the external policy. Reenable must explicitly review
	// taking it over again, including stopping a formerly managed service.
	if (!enabled && !managed && resume_managed !== true) return { ops, errors, conflicts };
	let sections = filter(keys(snapshot.usteer || {}), key => snapshot.usteer[key].type == 'usteer');
	if (length(sections) != 1) fail('steering_conflict', 'Exactly one usteer configuration is required');
	if (enabled && (!intent.wifi.enabled || !intent.wifi.roaming.k || !intent.wifi.roaming.v))
		fail('steering_roaming_required', 'Steering requires enabled Wi-Fi and 802.11k/v');
	if (enabled && (!cap.usteer || cap.dawn || cap.usteer_support?.conflicting_backend))
		fail('steering_dependency', 'Official usteer is required and other steering services must be stopped');
	if (enabled && cap.usteer_support?.supported !== true)
		fail('steering_unsupported', 'Installed usteer cannot provide the required advisory policy');
	if (enabled && cap.usteer_support?.boot_enabled !== true)
		fail('steering_boot_disabled', 'Enable the usteer startup service before managing steering');
	if (length(errors)) return { ops, errors, conflicts };
	let name = sections[0], section = snapshot.usteer[name];
	// Disabling a managed service retains ownership and its restoration values.
	// A future full Mesh release still restores the configuration from first takeover.
	let desired = steering_options(intent);
	for (let option, after in desired) {
		let before = section.values[option] ?? null;
		push(ops, {config:'usteer',section:name,type:'usteer',option,before:clone(before),after:clone(after),
			reason:'managed advisory roaming',changed:!equal(before,after)});
	}
	if (!managed) push(conflicts, {config:'usteer',section:name,
		message:'Existing usteer policy is taken over for the managed SSID and restored when Mesh is disabled'});
	return { ops, errors, conflicts };
}

export function steering_health(options, running, config, devices) {
	let checks = [];
	if (options.enabled == '0') return [{name:'usteer_stopped',ok:running === false}];
	push(checks,{name:'usteer_running',ok:running === true && type(config)=='object'});
	if (type(config) != 'object') return checks;
	for (let option, expected in options) {
		if (index(['enabled','network'],option)>=0) continue;
		let actual = config[option];
		if (expected == null) {
			// Omitted options and empty lists/strings are usteer's defaults.
			push(checks,{name:'usteer_'+option,ok:actual==null || actual=='' || type(actual)=='array' && !length(actual)});
		} else if (type(expected)=='array') push(checks,{name:'usteer_'+option,ok:equal(actual,expected)});
		else if (option=='node_up_script') push(checks,{name:'usteer_'+option,ok:actual===expected});
		else if (index(['local_mode','ipv6','assoc_steering','load_kick_enabled'],option)>=0)
			push(checks,{name:'usteer_'+option,ok:type(actual)=='bool' && actual==(expected=='1')});
		else push(checks,{name:'usteer_'+option,ok:type(actual)=='int' && actual==int(expected)});
	}
	push(checks,{name:'usteer_control_interfaces',ok:type(config.interfaces)=='array' &&
		type(devices)=='array' && length(devices)>0 && equal(sort([...config.interfaces]),sort([...devices]))});
	return checks;
}
