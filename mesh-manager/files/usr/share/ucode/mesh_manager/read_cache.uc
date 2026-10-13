// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { copy_json } from 'mesh_data';

// The caller must still read and validate the entire private file on every call.
// One bounded entry, no inode/mtime shortcut; callers receive independent values.
export function json_reader() {
	let raw, value;
	return content => {
		if(type(content)!='string') { raw=null;value=null;return null; }
		if(raw!=null && content===raw)return copy_json(value);
		raw=null;value=null;
		let parsed=json(content);
		if(length(content)<=262144) { raw=content;value=parsed;return copy_json(parsed); }
		return parsed;
	};
}
