// SPDX-License-Identifier: GPL-2.0-only
'use strict';

// Run only during configuration preflight. Status polling never invokes this
// helper. Use an already-up loopback interface so the installed hostap adapter
// can be checked without creating an interface or changing its flags.
export const LINK_FLAGS_PROBE = `
import { readfile } from 'fs';
import { wdev_set_up } from '/usr/share/hostap/common.uc';
let path='/sys/class/net/lo/flags', before=readfile(path);
if (before==null || !(int(trim(before),16)&1)) exit(2);
let error=wdev_set_up('lo',true), after=readfile(path);
if (after!==before) exit(2);
if (error==null) exit(0);
if (error=='Could not set the interface flags') exit(42);
exit(2);
`;

export function wireless_link_compatibility(run) {
	let result=run(['/usr/bin/ucode','-e',LINK_FLAGS_PROBE],'',1500);
	return result?.code===0 ? 'supported' : result?.code===42 ? 'incompatible' : 'unavailable';
}
