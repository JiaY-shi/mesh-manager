// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { history_pager } from './history_page.uc';
import { history_records as local_records, clear_history as clear_local } from './runtime.uc';
import { history_records as cluster_records } from './advanced.uc';
import { now, boot, random } from './durable.uc';
import * as durable from './durable.uc';
import { pairing_service } from './pairing.uc';
import { clear_retained_history, validate_history_clear, history_cleanup_idle } from './history_retention.uc';

const page = history_pager({ now, boot, random,
	records: group => group == 'local' ? local_records() : cluster_records(group) });
export function history_call(request) {
	try {
		let args = request?.args || {};
		// Unix-root ubus callers have no injected SID; HTTP access is checked by
		// uhttpd/rpcd against the read-only history ACL on every request.
		return { ok: true, data: page(args, args.ubus_rpc_session || '00000000000000000000000000000000') };
	} catch (e) {
		let found = match('' + e, /([a-z_]+): ([^\n]+)/);
		return { ok: false, error: { code: found?.[1] || 'internal_error',
			message: found?.[2] || 'History is unavailable', retryable: found?.[1] == 'busy' } };
	}
}

export function history_clear_call(request) {
	try {
		let args=request?.args || {}; validate_history_clear(args);
		let result=durable.locked(() => {
			if (args.group=='local') {
				if (durable.load('identity.json')?.role=='root') history_cleanup_idle(pairing_service(durable).state());
				return clear_local(args);
			}
			let pair=pairing_service(durable); pair.root();
			let state=pair.state(), result=clear_retained_history(state,args,boot());
			if (result.cleared && !result.replayed) durable.save('cluster.json',state);
			return result;
		},5);
		return {ok:true,data:result};
	} catch(e) {
		let found=match(''+e,/([a-z_]+): ([^\n]+)/);
		return {ok:false,error:{code:found?.[1] || 'internal_error',
			message:found?.[2] || 'History cleanup failed',retryable:found?.[1]=='busy'}};
	}
}
