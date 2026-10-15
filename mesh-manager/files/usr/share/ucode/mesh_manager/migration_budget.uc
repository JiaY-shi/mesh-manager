// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';

export function migration_budget(bytes) {
	if (type(bytes)!='int' || bytes<0 || bytes>262144)
		die('migration_limit: Controller transfer exceeds its resource bound');
	// Lazy compilation and the preceding snapshot can leave unreachable VM
	// objects until the periodic collector. Budget live data after collecting
	// those objects; the 8 MiB reserve and transfer multiplier remain intact.
	gc('collect');
	let file=fs.open('/proc/meminfo','re'),raw=file?.read(16385),tail=file?.read(1);
	file?.close();
	if (type(raw)!='string' || !length(raw) || length(raw)>16384 || tail!='' ||
		index(raw,'\0')>=0 || substr(raw,-1)!='\n')
		die('resource_unavailable: Cannot read complete bounded memory inventory');
	let available=filter(split(raw,'\n'),line=>index(line,'MemAvailable:')==0),
		value=length(available)==1 ? match(available[0],/^MemAvailable: +([0-9]+) +kB$/) : null;
	if (!value || length(value[1])>12)
		die('resource_unavailable: Invalid available memory inventory');
	// Keep the existing 8 MiB reserve in addition to transfer parsing/copies.
	if (int(value[1])*1024 < 8*1024*1024+bytes*4+262144)
		die('insufficient_resources: Controller migration requires the 8 MiB reserve and bounded transfer workspace');
}
