// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { clone, equal } from './model.uc';
import { backhaul_mode } from './radio_modes.uc';

export function planning_errors(p) {
	if (p == null) return [];
	if (type(p) != 'object' || length(filter(keys(p), k => index(
		['enabled', 'bands', 'six_ghz', 'channel', 'power', 'max_txpower_dbm', 'country'], k) < 0)) ||
		type(p.enabled) != 'bool' || type(p.bands) != 'array' || !length(p.bands) || length(p.bands) > 3 ||
		length(uniq(p.bands)) != length(p.bands) || length(filter(p.bands, b => index(['2g', '5g', '6g'], b) < 0)) ||
		index(['off', 'prefer', 'require'], p.six_ghz) < 0 || index(['keep', 'auto'], p.channel) < 0 ||
		index(['keep', 'auto'], p.power) < 0 || type(p.max_txpower_dbm) != 'int' ||
		p.max_txpower_dbm < 1 || p.max_txpower_dbm > 30 || p.six_ghz != 'off' && index(p.bands, '6g') < 0 ||
		p.country != null && (type(p.country) != 'string' || length(p.country)!=2 || !match(p.country, /^[A-Z]{2}$/)))
		return ['Invalid automatic band, channel or power policy'];
	return [];
}

export function planned_power(limit, candidates) {
	// libiwinfo candidates are deliberately unscoped. They select a conservative
	// requested value, never prove channel support. Driver readback gates confirm.
	// Nonzero calibration offsets cannot safely map this list to netifd dBm.
	if (type(limit)!='int' || limit<1 || limit>30 || candidates?.status!='complete' ||
		candidates.complete!==true || candidates.truncated!==false ||
		candidates.scope!='operating_channel_unknown' || candidates.channel!==null || candidates.offset_db!==0 ||
		type(candidates.raw_dbm)!='array' || !length(candidates.raw_dbm) || length(candidates.raw_dbm)>64 ||
		length(uniq(candidates.raw_dbm))!=length(candidates.raw_dbm) ||
		length(filter(candidates.raw_dbm,p=>type(p)!='int' || p<0 || p>63)))return null;
	let allowed=filter(candidates.raw_dbm,p=>p<=limit),selected=null;
	for (let power in allowed) selected=selected==null ? power : max(selected,power);
	return selected;
}

// These are only inputs to recompilation. The transaction still checks its
// secret seal over the complete raw snapshot, intent, ownership and exact ops.
export function approved_radio_choices(ops) {
	if (type(ops)!='array' || length(ops)>4096) return null;
	let result={},reasons={'planned client channel':'channel','planned client width':'htmode','planned client power':'txpower'};
	function full(value,pattern) { return match(value,pattern)?.[0]===value; }
	for (let op in ops) {
		let option=reasons[op?.reason];
		if (option==null) continue;
		if (op.config!='wireless' || op.type!='wifi-device' || op.option!=option ||
			type(op.section)!='string' || !full(op.section,/^[A-Za-z0-9_]{1,64}$/) ||
			type(op.after)!='string') return null;
		if (option=='htmode') {
			if (!full(op.after,/^(HT|VHT|HE)(20|40|80|160)$/)) return null;
		} else if (!full(op.after,/^(0|[1-9][0-9]{0,2})$/) || ''+int(op.after)!=op.after ||
			int(op.after)>(option=='channel'?233:30) || option=='channel' && int(op.after)<1) return null;
		result[op.section] ||= {};
		if (option in result[op.section]) return null;
		result[op.section][option]=op.after;
	}
	return result;
}

function readback_lines(raw, ifname, phyindex) {
	if (type(raw)!='string' || !length(raw) || length(raw)>4096 || substr(raw,-1)!='\n' || index(raw,'\0')>=0)return null;
	let lines=split(raw,'\n'),names=[],phys=[];
	for (let line in lines) {
		let name=match(line,/^Interface ([A-Za-z0-9_.-]+)$/),phy=match(line,/^[ \t]+wiphy ([0-9]+)$/);
		if (name)push(names,name[1]);
		if (phy)push(phys,int(phy[1]));
	}
	return length(names)==1 && names[0]==ifname && length(phys)==1 && phys[0]==phyindex ? lines : null;
}
export function running_power(raw, ifname, phyindex) {
	let lines=readback_lines(raw,ifname,phyindex),powers=[];
	if (!lines)return null;
	for (let line in lines) {
		let power=match(line,/^[ \t]+txpower ([0-9]+)\.([0-9]{2}) dBm$/);
		if (power)push(powers,int(power[1])*100+int(power[2]));
	}
	return length(powers)==1 && powers[0]<=6300 ? powers[0] : null;
}
export function running_channel(raw, ifname, phyindex) {
	let lines=readback_lines(raw,ifname,phyindex),channels=[];
	if (!lines)return null;
	for (let line in lines) {
		let row=match(line,/^[ \t]+channel ([0-9]+) \(([0-9]+) MHz\), width: ([0-9]+) MHz, center1: ([0-9]+) MHz(, center2: ([0-9]+) MHz)?$/);
		if (row)push(channels,{channel:int(row[1]),frequency_mhz:int(row[2]),width_mhz:int(row[3]),center1_mhz:int(row[4]),center2_mhz:int(row[6] || '0')});
	}
	return length(channels)==1 ? channels[0] : null;
}
function channel_frequency(channel,band) {
	if (channel<1 || channel>233)return null;
	return band=='2g' ? channel==14 ? 2484 : 2407+channel*5 :
		band=='5g' ? (channel>=182 && channel<=196 ? 4000 : 5000)+channel*5 :
		band=='6g' ? channel==2 ? 5935 : 5950+channel*5 : null;
}
export function channel_matches(config, observed, shared) {
	if (type(config.channel)!='string' || match(config.channel,/^[1-9][0-9]{0,2}$/)?.[0]!==config.channel ||
		!observed || observed.center2_mhz!=0)return false;
	let channel=int(config.channel),width=int(match(config.htmode || '',/^(HT|VHT|HE)(20|40|80|160)$/)?.[2]);
	if (index([20,40,80,160],width)<0 || width!=observed.width_mhz ||
		observed.frequency_mhz!=channel_frequency(observed.channel,config.band))return false;
	let first=channel,base;
	if (width!=20) {
		if (config.band=='6g')base=1;
		else if (config.band=='5g')base=channel>=36 && channel<=64 ? 36 : channel>=100 && channel<=144 ? 100 : channel>=149 && channel<=177 ? 149 : null;
		if (base==null)return false;
		first=base+int((channel-base)/(width/5))*int(width/5);
	}
	let center=width==20 ? channel_frequency(channel,config.band) : channel_frequency(first+(width/20-1)*2,config.band);
	if (observed.center1_mhz!=center)return false;
	if (observed.channel==channel)return true;
	// Native hostapd may exchange the HT40 primary/secondary pair after its
	// coexistence scan. The complete approved wide block and width stay fixed.
	return !shared && config.band=='5g' && width>=40 &&
		observed.channel>=first && observed.channel<=first+(width/20-1)*4 &&
		int((channel-base)/8)==int((observed.channel-base)/8) &&
		(observed.channel==channel-4 || observed.channel==channel+4);
}

function permitted(row, band) {
	return row?.band == band && type(row.channel) == 'int' && row.channel > 0 && row.channel <= 233 &&
		row.flags_known === true && type(row.flags) == 'array' &&
		!length(filter(row.flags, f => index(['disabled', 'no_ir', 'radar', 'no_20mhz'], f) >= 0)) &&
		type(row.max_tx_power_mbm) == 'int' && row.max_tx_power_mbm >= 100;
}
function block(rows, primary, width, mode) {
	if (index(primary.flags,'no_he')>=0 && substr(mode,0,2)=='HE') return null;
	if (width == 20) return [primary];
	if (primary.band == 2) return null;
	let count = width / 20, first;
	if (primary.band == 6) first = 1 + int((primary.channel - 1) / (count * 4)) * count * 4;
	else if (primary.channel >= 36 && primary.channel <= 64) first = 36 + int((primary.channel - 36) / (count * 4)) * count * 4;
	else if (primary.channel >= 100 && primary.channel <= 144) first = 100 + int((primary.channel - 100) / (count * 4)) * count * 4;
	else if (primary.channel >= 149 && primary.channel <= 177) first = 149 + int((primary.channel - 149) / (count * 4)) * count * 4;
	else return null;
	let members = [];
	for (let n = 0; n < count; n++) {
		let member = filter(rows, row => row.channel == first + 4 * n && permitted(row, primary.band) &&
			!(substr(mode,0,2)=='HE' && index(row.flags,'no_he')>=0) &&
			index(row.flags, width == 80 ? 'no_80mhz' : width == 160 ? 'no_160mhz' :
				n % 2 == 0 ? 'no_ht40_plus' : 'no_ht40_minus') < 0)[0];
		if (!member) return null;
		push(members, member);
	}
	return members;
}
function modes(radio) {
	return filter(radio.band == '2g' ? ['HE20', 'HT20'] : radio.band == '6g' ? ['HE80', 'HE40', 'HE20'] :
		['HE80', 'VHT80', 'HE40', 'VHT40', 'HT40', 'HE20', 'VHT20', 'HT20'],
		candidate => index(radio.htmodes || [], candidate) >= 0);
}
export function planning_radios(intent, cap) {
	let p = intent.wifi?.planning;
	if (!p?.enabled || length(planning_errors(p))) return clone(intent.wifi?.radios || []);
	return map(filter(cap.radios || [], r => index(intent.wifi.radios || [], r.name) >= 0 &&
		index(p.bands, r.band) >= 0 && (r.band != '6g' || p.six_ghz != 'off')), r => r.name);
}

export function committed_radio_choices(intent,cap,owned) {
	let p=intent.wifi?.planning, ops=[];
	if (!p?.enabled) return {};
	// Ownership retains its original reason for restoration. A field first
	// claimed by coordinated backhaul may later belong to client planning.
	for (let name in planning_radios(intent,cap)) {
		let shared=intent.backhaul.mode!='wired' && intent.local.mesh_radio==name;
		for (let option,reason in {'channel':'planned client channel','htmode':'planned client width','txpower':'planned client power'}) {
			if (option=='txpower' ? p.power!='auto' : shared || p.channel!='auto') continue;
			let matches=filter(owned || [],o=>o.config=='wireless' && o.type=='wifi-device' && o.section==name && o.option==option);
			if (length(matches)!=1) return null;
			push(ops,{...matches[0],reason});
		}
	}
	return approved_radio_choices(ops);
}

// A reviewed plan uses only legal driver frequencies and passive survey data.
// A country change needs its own reviewed apply before automatic RF planning.
// There are no autonomous reloads, off-channel scans or MLO changes.
export function radio_plan(intent, snapshot, cap, owned) {
	let p = intent.wifi?.planning, errors = map(planning_errors(p), message => ({ code: 'invalid_planning', message })),
		ops = [], warnings = [], effective = [];
	function fail(code, message) { push(errors, { code, message }); }
	function field(radio, option, after, reason) {
		let before = snapshot.wireless?.[radio]?.values?.[option] ?? null;
		push(ops, { config: 'wireless', section: radio, option, type: 'wifi-device', before, after,
			reason, changed: !equal(before, after) });
	}
	if (length(errors)) return { errors, ops, warnings, effective };
	if (cap.migration_metadata===true) {
		for (let owner in owned || []) {
			if (owner.config!='wireless' || index(['planned client channel','planned client width',
				'planned client power','reviewed radio country'],owner.reason)<0) continue;
			if (!equal(snapshot.wireless?.[owner.section]?.values?.[owner.option] ?? null,owner.after))
				fail('ownership_conflict','Committed radio settings changed outside Mesh Manager');
			else field(owner.section,owner.option,clone(owner.after),owner.reason);
		}
		push(warnings,'Controller migration preserves the committed radio configuration');
		return {errors,ops:length(errors)?[]:ops,warnings,effective};
	}
	if (!p?.enabled) {
		for (let owner in owned || []) {
			if (owner.config != 'wireless' || index(['planned client channel', 'planned client width', 'planned client power', 'reviewed radio country'], owner.reason) < 0) continue;
			if (!equal(snapshot.wireless?.[owner.section]?.values?.[owner.option] ?? null, owner.after))
				fail('ownership_conflict', 'Planned radio field changed outside Mesh Manager');
			else if (owner.option == 'country' && p?.country != null)
				field(owner.section, 'country', p.country, 'reviewed radio country');
			else if (!(intent.backhaul.mode != 'wired' && intent.local.mesh_radio == owner.section && index(['channel','htmode'], owner.option) >= 0))
				field(owner.section, owner.option, clone(owner.before), 'restore original client radio planning');
		}
		if (p?.country != null)
			for (let radio in cap.radios || [])
				if (index(intent.wifi.radios || [], radio.name) >= 0 && index(p.bands, radio.band) >= 0 &&
					!length(filter(ops, op => op.section == radio.name && op.option == 'country')))
					field(radio.name, 'country', p.country, 'reviewed radio country');
		return { errors, ops: length(errors) ? [] : ops, warnings, effective };
	}
	let names = planning_radios(intent, cap), radios = filter(cap.radios || [], r => index(names, r.name) >= 0);
	let six = filter(radios, r => r.band == '6g');
	if (p.six_ghz == 'require' && !length(six)) fail('six_ghz_unavailable', 'This node has no selected 6 GHz radio');
	else if (p.six_ghz == 'prefer' && !length(six)) push(warnings, 'This node uses its ordinary bands because no selected 6 GHz radio is available');
	if (length(six) && intent.wifi.enabled && intent.wifi.encryption != 'sae-mixed') fail('six_ghz_security', '6 GHz requires WPA3-capable encryption and protected management frames');
	if (!length(radios)) fail('planning_unavailable', 'No selected radio matches the requested bands');
	for (let radio in radios) {
		let observed = cap.planning?.[radio.name], band = { '2g': 2, '5g': 5, '6g': 6 }[radio.band],
			shared = intent.backhaul.mode != 'wired' && intent.local.mesh_radio == radio.name,
			reviewed = cap.approved_radio_choices!=null, choice=cap.approved_radio_choices?.[radio.name];
		if (p.country != null) {
			let before = snapshot.wireless?.[radio.name]?.values?.country ?? null;
			if (p.country != before && (p.channel != 'keep' || p.power != 'keep')) {
				fail('regulatory_refresh_required', 'Apply the reviewed country with channels and power kept, then preview automatic planning again'); continue;
			}
			field(radio.name, 'country', p.country, 'reviewed radio country');
		}
		if (p.channel == 'keep' && p.power == 'keep') continue;
		if (observed?.regulatory?.country_match !== true || observed.frequencies?.status != 'complete' ||
			observed.frequencies.truncated || type(observed.frequencies.items) != 'array' || length(observed.frequencies.items) > 256) {
			fail('planning_unavailable', 'Fresh legal frequencies and country agreement are required for radio planning'); continue;
		}
		let rows = filter(observed.frequencies.items, row => permitted(row, band)),
			requested_modes = shared ? [backhaul_mode(cap.radios,radio.name,intent.backhaul.htmode,intent.backhaul.channel).htmode] : p.channel == 'auto' ?
				(reviewed ? [choice?.htmode] : modes(radio)) : [snapshot.wireless[radio.name].values.htmode],
			requested_mode, width, candidates;
		for (let candidate_mode in requested_modes) {
			if (index(radio.htmodes || [],candidate_mode)<0) continue;
			let candidate_width = int(match(candidate_mode || '', /([0-9]+)$/)?.[1]);
			if (index([20,40,80,160], candidate_width) < 0) continue;
			let legal = filter(rows, row => block(rows, row, candidate_width, candidate_mode) != null &&
				(band != 2 || index([1,6,11], row.channel) >= 0) && (band != 6 || (row.channel - 5) % 16 == 0));
			if (!length(legal)) continue;
			requested_mode = candidate_mode; width = candidate_width; candidates = legal; break;
		}
		if (index([20, 40, 80, 160], width) < 0) { fail('planning_unavailable', 'Radio width cannot be verified'); continue; }
		let selected;
		if (shared || p.channel == 'keep') {
			let channel = shared ? intent.backhaul.channel : int(snapshot.wireless[radio.name].values.channel);
			selected = filter(rows, row => row.channel == channel && block(rows, row, width, requested_mode) != null)[0];
		} else if (reviewed) {
			selected=filter(candidates,row=>''+row.channel==choice?.channel)[0];
		} else {
			// Separate adjacent APs deterministically when passive survey data is
			// absent. Unknown interference stays unknown; it is never reported as
			// an RF optimization measurement.
			let ordinal = int(substr(intent.local.mac, -2), 16), ranked = clone(candidates), measured =
				filter(ranked, row => type(observed.survey?.['' + row.frequency_mhz]?.busy_percent) == 'int');
			if (length(measured) == length(ranked) && length(measured)) {
				let lowest = 100;
				for (let row in measured) lowest = min(lowest, observed.survey['' + row.frequency_mhz].busy_percent);
				ranked = filter(measured, row => observed.survey['' + row.frequency_mhz].busy_percent == lowest);
			}
			sort(ranked, (a, b) => a.channel - b.channel);
			selected = length(ranked) ? ranked[ordinal % length(ranked)] : null;
		}
		if (!selected || !requested_mode) { fail('planning_unavailable', 'No complete legal channel block satisfies the radio policy'); continue; }
		if (!shared && p.channel == 'auto') {
			push(warnings,'Automatic channel choices use passive measurements when available, otherwise deterministic legal allocation');
			field(radio.name, 'channel', '' + selected.channel, 'planned client channel');
			field(radio.name, 'htmode', requested_mode, 'planned client width');
		}
		let members = block(rows, selected, width, requested_mode), ceiling = 100;
		for (let row in members) ceiling = min(ceiling, int(row.max_tx_power_mbm / 100));
		let limit=min(p.max_txpower_dbm,ceiling), maximum=p.power=='auto' ? planned_power(limit,observed.power) : null,
			power=p.power=='auto' && reviewed ? (type(choice?.txpower)=='string' &&
				''+int(choice.txpower)==choice.txpower ? int(choice.txpower) : null) : maximum;
		if (reviewed && p.power=='auto' && (maximum==null || power==null || power<0 || power>limit ||
			index(observed.power.raw_dbm,power)<0)) power=null;
		if (p.power=='auto' && power==null) {
			fail('power_unavailable','No complete driver power candidates satisfy the requested ceiling'); continue;
		}
		if (p.power=='auto') push(warnings,'Driver power candidates are unscoped; actual driver power must pass the ceiling check before confirmation');
		if (p.power == 'auto') field(radio.name, 'txpower', '' + power, 'planned client power');
		push(effective, { radio: radio.name, band: radio.band, channel: selected.channel, htmode: requested_mode,
			txpower_dbm: p.power == 'auto' ? power : null, shared_backhaul: shared,
			load_observed: observed.survey?.['' + selected.frequency_mhz]?.busy_percent != null });
	}
	return { errors, ops: length(errors) ? [] : ops, warnings, effective };
}
