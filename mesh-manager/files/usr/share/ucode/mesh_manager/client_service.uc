// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as durable from './durable.uc';
import * as observations from './client_events.uc';
import { presence } from './advanced.uc';
import { client_pages } from './client_page.uc';

const pages=client_pages({...durable,presence,observations:observations.status,
	frame:()=>durable.locked(()=>({identity:durable.load('identity.json'),local:durable.load('state.json'),
		cluster:durable.load('cluster.json')}),5)});
export function client_call(method,request) {
	try {
		let args=request?.args || {};
		return {ok:true,data:pages(method,args,args.ubus_rpc_session || '00000000000000000000000000000000')};
	} catch(e) {
		let found=match(''+e,/([a-z_]+): ([^\n]+)/);
		return {ok:false,error:{code:found?.[1] || 'internal_error',message:found?.[2] || 'Client observations unavailable',
			retryable:found?.[1]=='busy'}};
	}
}
