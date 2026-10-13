// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as uloop from 'uloop';

// Collect at an independent event-loop boundary. Allocation-triggered -g
// collection in the supported VM can interrupt native map/filter callbacks
// whose temporary results are not VM roots. Never collect inside business work.
export function collection_start() {
	let timer;
	timer = uloop.timer(10000, () => {
		gc();
		timer.set(10000);
	});
	return () => timer.cancel();
}
