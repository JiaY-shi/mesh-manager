// SPDX-License-Identifier: GPL-2.0-only
'use strict';

function mode_list(value) {
	return type(value) == 'array' && length(value) > 0 && length(value) <= 64 &&
		!length(filter(value, mode => type(mode) != 'string' || length(mode) < 1 || length(mode) > 16)) &&
		length(uniq(value)) == length(value);
}

function channels(radio, frequencies) {
	let band = { '2g': 2, '5g': 5, '6g': 6 }[radio.band], rows = frequencies?.results;
	if (!band || type(rows) != 'array' || !length(rows) || length(rows) > 256 ||
		length(filter(rows, row => type(row) != 'object' || type(row.band) != 'int' ||
			type(row.channel) != 'int' || row.channel < 1 || row.channel > 233))) return null;
	let selected = map(filter(rows, row => row.band == band), row => row.channel);
	return length(selected) && length(uniq(selected)) == length(selected) ? selected : null;
}

function channel_list(value) {
	return type(value) == 'array' && length(value) > 0 && length(value) <= 256 &&
		!length(filter(value, channel => type(channel) != 'int' || channel < 1 || channel > 233)) &&
		length(uniq(value)) == length(value);
}

// Only configuration preflight reads iwinfo. Ordinary status must not probe
// every radio or turn an advisory cache into permission to configure it.
export function radio_modes(radios, cached, query, frequency_query) {
	return map(radios, radio => {
		let info, frequencies;
		if (cached !== true) {
			try { info = query(radio.name); } catch (e) {}
			try { frequencies = frequency_query?.(radio.name); } catch (e) {}
		}
		return { ...radio,
			htmodes: mode_list(info?.htmodes) ? info.htmodes : null,
			hwmodes: mode_list(info?.hwmodes) ? info.hwmodes : null,
			channels: cached !== true ? channels(radio, frequencies) : null };
	});
}

export function backhaul_mode(radios, name, requested, channel) {
	let matches = filter(radios || [], radio => radio.name == name), radio = matches[0];
	if (length(matches) != 1 || !mode_list(radio?.htmodes) || !mode_list(radio?.hwmodes))
		return { error: 'radio_capability_unknown' };
	let parsed = match(requested || '', /^(HT|VHT|HE)(20|40|80|160)$/);
	if (!parsed) return { error: 'radio_width_unsupported' };
	if (channel != null) {
		if (!channel_list(radio.channels)) return { error: 'radio_channel_unknown' };
		if (index(radio.channels, channel) < 0) return { error: 'radio_channel_unsupported' };
	}
	let generations = ['HE', 'VHT', 'HT'], hardware = { HE: 'ax', VHT: 'ac', HT: 'n' },
		start = index(generations, parsed[1]);
	for (let generation in slice(generations, start)) {
		let mode = generation + parsed[2];
		if (index(radio.hwmodes, hardware[generation]) >= 0 && index(radio.htmodes, mode) >= 0)
			return { htmode: mode };
	}
	// Preserve the coordinated width; never silently reduce 80/160 MHz to 40.
	return { error: 'radio_width_unsupported' };
}
