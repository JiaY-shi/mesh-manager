// SPDX-License-Identifier: GPL-2.0-only
'use strict';
'require baseclass';
'require mesh_manager.widgets as widgets';
'require mesh_manager.slow_rpc as slow';

var writable=false;
var probeSection,probeTarget,probeStart,probeTrace,probeDns,probeUpstream,probeAddress,probeLocalId,probeCancel,probeOutput,probeRunning=false,probeControl;
var radioSection,radioDetails,radioOutput,radioRefresh,radioCancel,radioControl,radioLocalId,radioRunning=false,radioLoaded=false,radioScopeChanged=false;
var radioPages=Object.create(null),radioFolds=Object.create(null);
var regulatorySection,regulatoryDetails,regulatoryOutput,regulatoryRefresh,regulatoryCancel,regulatoryControl,regulatoryLocalId,regulatoryRunning=false,regulatoryLoaded=false,regulatoryScopeChanged=false;
var regulatoryPages=Object.create(null),regulatoryFolds=Object.create(null);
function button(label,fn){return E('button',{type:'button','class':'cbi-button cbi-button-neutral',click:fn},[label]);}
function diagnosticBusy(){return probeRunning || radioRunning || regulatoryRunning;}
function updateChecks(){
	var busy=diagnosticBusy();
	if(probeStart){probeStart.disabled=probeTrace.disabled=!writable || busy || !probeTarget.value;
		probeDns.disabled=probeUpstream.disabled=probeAddress.disabled=!writable || busy || !probeLocalId;probeTarget.disabled=busy;probeCancel.disabled=!probeRunning;}
	if(radioRefresh){radioRefresh.disabled=!writable || busy || !radioLocalId;radioCancel.disabled=!radioRunning || radioControl?.cancelled;}
	if(regulatoryRefresh){regulatoryRefresh.disabled=!writable || busy || !regulatoryLocalId;regulatoryCancel.disabled=!regulatoryRunning || regulatoryControl?.cancelled;}
}
function probeFailure(error) {
	return ({rate_limited:_('Wait five seconds before starting another check.'),
		target_unavailable:_('The selected node is not currently available. Refresh its status before checking again.'),
		target_changed:_('The node address or identity changed during the check. Start a new check.'),
		job_cancelled:_('Check cancelled.'),not_authorized:_('Diagnostic permission is no longer available.'),
		request_timeout:_('The check timed out.'),backend_unavailable:_('The device diagnostic command is unavailable or returned an unsupported result.')})[error && error.code] || widgets.configurationError(error || {});
}
function runProbe(check) {
	var target=['local_dns','local_address_conflict','local_upstream_dns'].includes(check)?probeLocalId:probeTarget.value;
	if(diagnosticBusy() || !writable || !target)return;
	probeRunning=true;updateChecks();
	probeOutput.textContent=_('Queued');
	probeControl={progress:function(state){probeOutput.textContent=state==='running'?(check==='local_dns'?_('Checking local DNS…'):check==='local_upstream_dns'?_('Checking runtime DNS candidates…'):check==='local_address_conflict'?_('Checking local address conflict…'):_('Checking node connectivity…')):_('Queued');}};
	return slow.preview(probeControl,'run',{check:check,node_id:target},'mesh-manager.diag').then(function(reply){
		if(!reply || !reply.ok){probeOutput.textContent=probeFailure(reply && reply.error);return;}
		if(check==='node_trace'){renderTrace(reply.data);return;}
		if(check==='local_dns'){renderDns(reply.data);return;}
		if(check==='local_upstream_dns'){renderUpstreamDns(reply.data);return;}
		if(check==='local_address_conflict'){renderAddressConflict(reply.data);return;}
		var value=reply.data,labels={reachable:_('Replies received'),partial:_('Some replies missing'),no_reply:_('No ICMP reply'),duplicate_replies:_('Duplicate replies observed')};
		probeOutput.replaceChildren(widgets.facts([
			[_('Result'),widgets.status(labels[value.status] || _('Unknown'),value.status==='reachable'?'good':'warning')],
			[_('Management address'),value.address],[_('Packets received / sent'),value.received+' / '+value.transmitted],
			[_('Packet loss'),value.loss_percent.toFixed(1)+'%'],[_('Average round-trip time'),value.roundtrip_ms?value.roundtrip_ms.average.toFixed(3)+' ms':'-'],
			[_('Updated at'),new Date(value.observed_at*1000).toLocaleTimeString()]
		]));
	}).catch(function(error){probeOutput.textContent=probeFailure(error);}).finally(function(){
		probeRunning=false;updateChecks();
	});
}
function renderAddressConflict(value) {
	var labels={conflict_observed:_('Address conflict observed'),no_conflict_observed:_('No conflict observed in this check')};
	if(!value || value.scope!=='local_primary_ipv4' || !labels[value.status]){
		probeOutput.textContent=probeFailure({code:'backend_unavailable'});return;
	}
	probeOutput.replaceChildren(widgets.facts([
		[_('Result'),E('span',{title:value.status},[widgets.status(labels[value.status],value.status==='conflict_observed'?'warning':'good')])],
		[_('Scope'),_('Local primary IPv4')],[_('Management address'),value.address],
		[_('ARP probes / claims'),value.transmitted+' / '+value.claims],
		[_('Updated at'),new Date(value.observed_at*1000).toLocaleTimeString()]
	]),E('p',{'class':'mm-muted'},[_('No reply does not guarantee that the address is unused. This checks the current primary IPv4 only, not other addresses or IPv6.')]));
}
function renderDns(value) {
	var labels={answered:_('Local DNS replied'),no_reply:_('No DNS reply'),record_missing:_('Localhost record missing'),unexpected_answer:_('Unexpected non-loopback answer')};
	probeOutput.replaceChildren(widgets.facts([
		[_('Result'),widgets.status(labels[value.status] || _('Unknown'),value.status==='answered'?'good':'warning')],
		[_('DNS resolver'),value.resolver],[_('Query'),value.query+' ('+value.query_type+')'],
		[_('Answer'),value.addresses.join(', ') || '-'],[_('Updated at'),new Date(value.observed_at*1000).toLocaleTimeString()]
	]),E('p',{'class':'mm-muted'},[_('This checks the local DNS response only. It does not verify upstream DNS or Internet domain resolution.')]));
}
function renderUpstreamDns(value) {
	if(value?.schema!==1 || value.scope!=='runtime_netifd_dns' || value.node_id!==probeLocalId || !Array.isArray(value.resolvers) || value.resolvers.length>4 ||
		!Array.isArray(value.excluded) || value.excluded.length>16){probeOutput.textContent=probeFailure({code:'backend_unavailable'});return;}
	var names={answered:_('DNS replied'),empty_answer:_('Empty DNS answer'),no_reply:_('No DNS reply'),
		nxdomain:_('DNS name not found'),servfail:_('DNS server failure'),refused:_('DNS query refused'),
		truncated_requires_tcp:_('Truncated reply; TCP not checked'),
		local_candidate:_('Local resolver; not checked'),nonunicast_candidate:_('Not a unicast resolver'),
		not_tested_limit:_('Not checked within the candidate limit'),malformed_reply:_('No verified DNS reply'),
		unverified_reply:_('No verified DNS reply'),invalid_reply:_('No verified DNS reply'),
		formerr:_('DNS query format rejected'),notimp:_('DNS query not supported'),other_rcode:_('Other DNS response code'),
		network_unreachable:_('DNS endpoint unreachable'),receive_limit:_('DNS receive limit reached'),process_timeout:_('The check timed out.'),
		invalid_target:_('DNS candidate unavailable'),entropy_unavailable:_('DNS query entropy unavailable'),clock_unavailable:_('Monotonic clock unavailable'),
		socket_unavailable:_('DNS transport unavailable'),send_failed:_('DNS query could not be sent'),receive_failed:_('DNS reply could not be read'),
		budget_exceeded:_('The check timed out.')};
	var records=value.resolvers.concat(value.excluded);
	probeOutput.replaceChildren(widgets.facts([
		[_('Result'),radioState(value.status)],[_('DNS candidates / checked'),value.candidate_count+' / '+value.tested_count],
		[_('Query'),'. (NS / UDP)'],[_('Updated at'),new Date(value.observed_at*1000).toLocaleTimeString()]
	]),radioPager('runtime-dns-candidates',[_('DNS resolver'),_('Source interface'),_('Result'),_('Elapsed time')],records,function(row){
		return [row.resolver,(row.sources || []).join(', ') || _('Unknown'),
			widgets.status(names[row.status] || _('Unknown'),row.status==='answered'?'good':'neutral'),
			row.elapsed_ms==null?'-':row.elapsed_ms.toFixed(1)+' ms'];
	},_('No testable runtime DNS candidates')),
	E('p',{'class':'mm-muted'},[_('Checks IPv4 DNS candidates reported by netifd. Custom DNS policies, proxies, IPv6 and TCP are not checked; a reply does not prove Internet access.')]));
}
function renderTrace(value) {
	var labels={target_reply:_('Target address replied'),hop_limit:_('Hop limit reached'),incomplete:_('Trace ended before reaching the target'),unreachable:_('Unreachable response')};
	var reasons={network_unreachable:_('Network unreachable'),host_unreachable:_('Host unreachable'),protocol_unreachable:_('Protocol unreachable'),
		prohibited:_('Blocked by network policy'),fragmentation_needed:_('Packet needs fragmentation')};
	probeOutput.replaceChildren(widgets.facts([
		[_('Result'),widgets.status(labels[value.status] || _('Unknown'),value.status==='target_reply'?'good':'warning')],
		[_('Management address'),value.address],[_('Updated at'),new Date(value.observed_at*1000).toLocaleTimeString()]
	]),widgets.table([_('Hop'),_('Address'),_('Round-trip time'),_('Result')],value.hops.map(function(hop){
		return [String(hop.hop),hop.address || '-',hop.roundtrip_ms==null?'-':hop.roundtrip_ms.toFixed(3)+' ms',
			hop.status==='no_reply'?_('No reply'):hop.status==='reply'?_('Reply received'):reasons[hop.reason] || _('Unreachable response')];
	}),_('No hop observations')));
}
function radioState(value){
	return widgets.status(({complete:_('Complete'),partial:_('Incomplete'),unavailable:_('Unavailable')})[value] || _('Unknown'),value==='complete'?'neutral':'warning');
}
function radioPager(key,headers,items,row,empty,pages){
	pages=pages || radioPages;
	var page=Math.min(pages[key] || 0,Math.max(0,Math.ceil(items.length/10)-1)),root=E('div',{'class':'mm-paged-table','data-mm-pager':key});
	function draw(){
		pages[key]=page;root.dataset.mmPage=page;
		root.replaceChildren(widgets.table(headers,items.slice(page*10,page*10+10).map(row),empty));
		if(items.length<=10)return;
		function move(label,symbol,target,disabled){return E('button',{type:'button','class':'cbi-button cbi-button-neutral mm-page-button','aria-label':label,'data-tooltip':label,
			disabled:disabled || null,click:function(){page=target;draw();}},[symbol]);}
		root.appendChild(E('div',{'class':'mm-pagination','aria-label':_('Pagination')},[
			E('span',{'class':'mm-pagination-count'},[_('Records %s-%s of %s').format(page*10+1,Math.min(page*10+10,items.length),items.length)]),
			move(_('Previous page'),'\u2039',page-1,page===0),E('span',{'class':'mm-pagination-page'},[_('Page %s of %s').format(page+1,Math.ceil(items.length/10))]),
			move(_('Next page'),'\u203a',page+1,(page+1)*10>=items.length)]));
	}
	draw();return root;
}
function radioFold(key,title,children,folds){
	folds=folds || radioFolds;
	var details=widgets.details(title,children,folds[key]===true);
	details.dataset.mmDetail=key;
	details.addEventListener('toggle',function(){if(details.isConnected)folds[key]=details.open;});return details;
}
function renderRadios(value){
	if(value?.schema!==1 || value.scope!=='local_radios' || value.node_id!==radioLocalId || !Array.isArray(value.radios) || value.radios.length>8){
		radioOutput.textContent=probeFailure({code:value?.node_id && value.node_id!==radioLocalId?'target_changed':'backend_unavailable'});return;
	}
	var rows=value.radios,contents=[widgets.table([_('Radio'),_('PHY'),_('Backend channel'),_('Reference power'),_('Status')],rows.map(function(r){
		var reference=r.reported || {};
		return [r.radio,r.phy || _('Unknown'),reference.channel==null?_('Unknown'):String(reference.channel),
			reference.txpower_dbm==null || reference.txpower_source==='zero_unverified'?_('Unknown'):reference.txpower_dbm+' dBm',radioState(r.status)];
	}),_('No radio capabilities available'))];
	rows.forEach(function(r){
		var channels=r.channels || {},power=r.power || {},key='radio-capabilities-'+r.radio;
		contents.push(radioFold(key+'-details',_('Capabilities: %s').format(r.radio),[
			widgets.facts([[_('Channel list'),radioState(channels.status)],[_('Power list'),radioState(power.status)]],true),
			radioFold(key+'-channels',_('Backend channel list'),[
				radioPager(key+'-channels',[_('Band'),_('Channel'),_('Frequency'),_('Restrictions')],channels.items || [],function(c){
					var names={no_ir:_('No initiating radiation'),indoor_only:_('Indoor only'),no_10mhz:_('No 10 MHz'),no_20mhz:_('No 20 MHz'),
						'no_ht40+':_('No HT40+'),'no_ht40-':_('No HT40-'),no_80mhz:_('No 80 MHz'),no_160mhz:_('No 160 MHz'),no_he:_('No HE')};
					return [c.band===2?'2.4 GHz':c.band+' GHz',String(c.channel),c.frequency_mhz+' MHz',
						(c.flags || []).map(function(flag){return names[flag] || _('Unknown');}).join(', ') || _('No exposed restrictions')];
				},_('Channel capabilities unavailable')),
				channels.truncated?E('p',{'class':'mm-muted'},[_('The displayed capability list is incomplete.')]):null
			]),radioFold(key+'-power',_('Backend power candidates'),[
				E('p',{'class':'mm-muted'},[_('The channel to which this list applies cannot be verified. These candidates cannot define a safe transmit-power limit.')]),
				E('p',{'class':'mm-muted'},[_('The backend may fall back internally or match the same channel number in another band.')]),
				radioPager(key+'-power',[_('Backend power candidate')],power.raw_dbm || [],function(p){return [p+' dBm'];},_('Power capabilities unavailable')),
				E('p',{'class':'mm-muted'},[_('Hardware power offset: %s').format(power.offset_db==null?_('Unknown'):power.offset_db+' dB')])
			])
		]));
	});
	contents.push(E('p',{'class':'mm-muted'},[_('Backend values are references and may use cached data. They do not prove current hardware state or actual transmit power.')]),
		E('p',{'class':'mm-muted'},[_('DFS requirements are not exposed by this channel list. An empty restrictions list does not mean that a channel is free of DFS or immediately usable.')]),
		E('p',{'class':'mm-muted'},[_('Updated at %s').format(new Date(value.observed_at*1000).toLocaleTimeString())]));
	if(value.status!=='complete' || value.truncated)contents.unshift(E('p',{'class':'mm-muted'},[_('Some radio capabilities are unavailable or incomplete.')])) ;
	radioOutput.replaceChildren.apply(radioOutput,contents);
}
function loadRadios(){
	if(diagnosticBusy() || !writable || !radioLocalId)return;
	var target=radioLocalId,control={cancelled:false,node_id:target};radioControl=control;radioRunning=true;radioLoaded=true;radioScopeChanged=false;updateChecks();
	radioOutput.textContent=_('Queued');
	function current(){return radioControl===control && !control.cancelled && radioLocalId===target;}
	control.progress=function(state){if(current())radioOutput.textContent=state==='running'?_('Reading radio capabilities…'):_('Queued');};
	return slow.preview(control,'run',{check:'local_radios',node_id:target},'mesh-manager.diag').then(function(reply){
		if(!current())return;
		if(!reply?.ok){radioOutput.textContent=probeFailure(reply?.error);return;}renderRadios(reply.data);
	}).catch(function(error){if(current())radioOutput.textContent=probeFailure(error);}).finally(function(){
		if(radioControl===control){radioRunning=false;updateChecks();}
	});
}
function cancelRadios(){
	var control=radioControl;if(!radioRunning || !control || control.cancelled || !control.cancel)return;
	control.cancelled=true;radioOutput.textContent=_('Cancelling check…');updateChecks();
	return control.cancel().then(function(){if(radioControl===control && radioLocalId===control.node_id)radioOutput.textContent=_('Check cancelled.');},function(error){
		if(radioControl===control && radioLocalId===control.node_id)radioOutput.textContent=probeFailure(error);
	});
}
function radioCapabilities(data){
	var nextId=data.cluster?.identity?.id;
	if(nextId!==radioLocalId && (radioLoaded || radioRunning)){
		radioLoaded=false;radioScopeChanged=true;radioPages=Object.create(null);radioFolds=Object.create(null);
		radioOutput.textContent=probeFailure({code:'target_changed'});
	}
	radioLocalId=nextId;
	if(!radioSection){
		radioRefresh=button(_('Refresh radio capabilities'),loadRadios);radioCancel=button(_('Cancel radio check'),cancelRadios);
		radioOutput=E('div',{'class':'mm-radio-capabilities-result',role:'status','aria-live':'polite'});
		radioDetails=widgets.details(_('View radio capabilities'),[
			E('p',{'class':'mm-muted'},[_('Reads local radio capabilities on demand. It does not scan, change radio settings or start disabled radios.')]),
			E('div',{'class':'mm-actions'},[radioRefresh,radioCancel]),radioOutput]);
		radioDetails.addEventListener('toggle',function(){if(radioDetails.open && !radioLoaded)loadRadios();});
		radioSection=widgets.section(_('Radio capabilities'),[radioDetails]);
	}
	if(!radioLoaded && !radioScopeChanged)radioOutput.textContent=!writable?_('Diagnostic permission is required to inspect radio capabilities.'):
		!radioLocalId?_('The device identity is not initialized. Radio inspection is unavailable.'):
		diagnosticBusy()?_('Another diagnostic check is running. Refresh after it finishes.') : '';
	updateChecks();return radioSection;
}
function regulatoryPower(value){return Number.isInteger(value)?String(value/100)+' dBm':_('Unknown');}
function regulatoryDomain(value){
	return value==='00'?_('World domain (00)'):value==='98'?_('Intersection domain (98)'):value==='99'?_('Unknown domain (99)'):value || _('Unknown');
}
function regulatorySource(value){
	return value==='device'?_('Device regulatory domain'):value==='global_fallback'?_('Global domain fallback'):_('Unavailable');
}
function regulatoryState(value){
	return widgets.status(value==='complete'?_('Query complete'):value==='partial'?_('Partial data'):_('Unavailable'),value==='complete'?'good':'warning');
}
function regulatoryDfs(value){
	var text={usable:_('CAC required'),unavailable:_('Radar unavailable'),available:_('Available at observation'),unknown:_('Unknown')};
	return E('span',{title:value || 'unknown'},[text[value] || _('Unknown')]);
}
function renderRegulatory(value){
	if(value?.schema!==1 || value.scope!=='local_regulatory' || value.source!=='nl80211' || value.node_id!==regulatoryLocalId ||
		value.write_approval!==false || value.transport_complete!==null || !Array.isArray(value.radios) || value.radios.length>8){
		regulatoryOutput.textContent=probeFailure({code:value?.node_id && value.node_id!==regulatoryLocalId?'target_changed':'backend_unavailable'});return;
	}
	var rows=value.radios,contents=[widgets.table([_('Radio'),_('PHY'),_('Regulatory domain'),_('Driver reported power'),_('Status')],rows.map(function(r){
		var domain=r.regulatory || {},current=r.current || {};
		return [r.radio,r.phy || _('Unknown'),E('span',{},[
			E('span',{},[regulatoryDomain(domain.alpha2)]),E('small',{'class':'mm-subtle'},[regulatorySource(domain.scope)])]),
			current.mlo?_('Unknown'):regulatoryPower(current.txpower_mbm),regulatoryState(r.status)];
	}),_('Regulatory data unavailable'))];
	rows.forEach(function(r){
		var domain=r.regulatory || {},current=r.current || {},frequencies=r.frequencies || {},key='regulatory-'+r.radio;
		contents.push(radioFold(key+'-details',_('Regulatory details: %s').format(r.radio),[
			widgets.facts([[_('Configured country'),regulatoryDomain(domain.configured_country)],[_('Domain source'),regulatorySource(domain.scope)],
				[_('Reported domain'),regulatoryDomain(domain.alpha2)],[_('Global domain'),regulatoryDomain(domain.global_alpha2)],
				[_('Driver reported frequency'),current.mlo || current.frequency_mhz==null?_('Unknown'):current.frequency_mhz+' MHz'],
				[_('Channel width'),current.mlo || !current.channel_width || current.channel_width==='unknown'?_('Unknown'):
					current.channel_width==='20_noht'?'20 MHz ('+_('No HT')+')':current.channel_width+' MHz']],true),
			current.mlo?E('p',{'class':'mm-muted'},[_('MLO operating data are unavailable in this check.')]):null,
			radioFold(key+'-frequencies',_('Frequency limits and DFS'),[
				E('p',{'class':'mm-muted'},[_('A usable DFS channel still requires CAC before transmission. Available is the observed kernel state, not a promise that it remains usable.')]),
				radioPager(key+'-frequencies',[_('Frequency'),_('Channel'),_('Regulatory power limit'),_('DFS state'),_('Required CAC'),_('Restrictions')],
					Array.isArray(frequencies.items)?frequencies.items:[],function(f){
						var restrictions={disabled:_('Disabled'),no_ir:_('No initiating radiation'),no_ibss:_('No IBSS'),radar:_('Radar detection required'),
							no_ht40_plus:_('No HT40+'),no_ht40_minus:_('No HT40-'),no_10mhz:_('No 10 MHz'),no_20mhz:_('No 20 MHz'),
							no_80mhz:_('No 80 MHz'),no_160mhz:_('No 160 MHz'),no_320mhz:_('No 320 MHz'),no_he:_('No HE'),no_eht:_('No EHT'),
							indoor_only:_('Indoor only'),ir_concurrent:_('Concurrent radiation condition'),'1mhz':_('1 MHz allowed'),'2mhz':_('2 MHz allowed'),
							'4mhz':_('4 MHz allowed'),'8mhz':_('8 MHz allowed'),'16mhz':_('16 MHz allowed')};
						var frequency=f.frequency_mhz+' MHz'+(f.frequency_offset_khz==null?'':' ('+f.frequency_offset_khz+' kHz)');
						return [frequency,f.channel==null?_('Unknown'):String(f.channel),regulatoryPower(f.max_tx_power_mbm),
							E('span',{title:f.dfs_age_ms==null?_('State age unknown'):_('State age: %s').format(f.dfs_age_ms+' ms')},[regulatoryDfs(f.dfs_state)]),
							f.dfs_cac_ms==null?_('Unknown'):f.dfs_cac_ms/1000+' s',
							f.flags_known!==true?_('Unknown'):(f.flags || []).map(function(flag){return restrictions[flag] || _('Unknown');}).join(', ') || _('No exposed restrictions')];
					},_('Frequency limits unavailable'),regulatoryPages),
				frequencies.truncated?E('p',{'class':'mm-muted'},[_('The displayed frequency list is incomplete.')]):null
			],regulatoryFolds)
		],regulatoryFolds));
	});
	contents.push(E('p',{'class':'mm-muted'},[_('Driver reported power is not measured over-the-air power. Regulatory limits are separate from current power and backend power candidates.')]),
		E('p',{'class':'mm-muted'},[_('This query covers known diagnostic fields and does not grant configuration approval. Disabled frequencies remain disabled even when a power limit is shown.')]),
		E('p',{'class':'mm-muted'},[_('Updated at %s').format(new Date(value.observed_at*1000).toLocaleTimeString())]));
	if(value.status!=='complete' || value.truncated)contents.unshift(E('p',{'class':'mm-muted'},[_('Some regulatory data are unavailable or incomplete.')])) ;
	regulatoryOutput.replaceChildren.apply(regulatoryOutput,contents);
}
function loadRegulatory(){
	if(diagnosticBusy() || !writable || !regulatoryLocalId)return;
	var target=regulatoryLocalId,control={cancelled:false,node_id:target};regulatoryControl=control;regulatoryRunning=true;regulatoryLoaded=true;regulatoryScopeChanged=false;updateChecks();
	regulatoryOutput.textContent=_('Queued');
	function current(){return regulatoryControl===control && !control.cancelled && regulatoryLocalId===target;}
	control.progress=function(state){if(current())regulatoryOutput.textContent=state==='running'?_('Reading regulatory limits…'):_('Queued');};
	return slow.preview(control,'run',{check:'local_regulatory',node_id:target},'mesh-manager.diag').then(function(reply){
		if(!current())return;
		if(!reply?.ok){regulatoryOutput.textContent=probeFailure(reply?.error);return;}renderRegulatory(reply.data);
	}).catch(function(error){if(current())regulatoryOutput.textContent=probeFailure(error);}).finally(function(){
		if(regulatoryControl===control){regulatoryRunning=false;updateChecks();}
	});
}
function cancelRegulatory(){
	var control=regulatoryControl;if(!regulatoryRunning || !control || control.cancelled || !control.cancel)return;
	control.cancelled=true;regulatoryOutput.textContent=_('Cancelling check…');updateChecks();
	return control.cancel().then(function(){if(regulatoryControl===control && regulatoryLocalId===control.node_id)regulatoryOutput.textContent=_('Check cancelled.');},function(error){
		if(regulatoryControl===control && regulatoryLocalId===control.node_id)regulatoryOutput.textContent=probeFailure(error);
	});
}
function regulatoryData(data){
	var nextId=data.cluster?.identity?.id;
	if(nextId!==regulatoryLocalId && (regulatoryLoaded || regulatoryRunning)){
		regulatoryLoaded=false;regulatoryScopeChanged=true;regulatoryPages=Object.create(null);regulatoryFolds=Object.create(null);
		regulatoryOutput.textContent=probeFailure({code:'target_changed'});
	}
	regulatoryLocalId=nextId;
	if(!regulatorySection){
		regulatoryRefresh=button(_('Refresh regulatory data'),loadRegulatory);regulatoryCancel=button(_('Cancel regulatory check'),cancelRegulatory);
		regulatoryOutput=E('div',{'class':'mm-regulatory-result',role:'status','aria-live':'polite'});
		regulatoryDetails=widgets.details(_('View regulatory limits'),[
			E('p',{'class':'mm-muted'},[_('Reads this device’s regulatory domain, frequency restrictions and DFS state on demand. It does not scan, set a country or change radio settings.')]),
			E('div',{'class':'mm-actions'},[regulatoryRefresh,regulatoryCancel]),regulatoryOutput]);
		regulatoryDetails.addEventListener('toggle',function(){if(regulatoryDetails.open && !regulatoryLoaded)loadRegulatory();});
		regulatorySection=widgets.section(_('Regulatory domain and DFS'),[regulatoryDetails],widgets.help(_('A global domain fallback is not a device-specific country. DFS age is elapsed time in that state, not a CAC countdown.')));
	}
	if(!regulatoryLoaded && !regulatoryScopeChanged)regulatoryOutput.textContent=!writable?_('Diagnostic permission is required to inspect regulatory data.'):
		!regulatoryLocalId?_('The device identity is not initialized. Regulatory inspection is unavailable.'):
		diagnosticBusy()?_('Another diagnostic check is running. Refresh after it finishes.') : '';
	updateChecks();return regulatorySection;
}
return baseclass.extend({attention:function(data,showEmpty){
	var state=data.attention;
	if(!state || !showEmpty && !state.total)return null;
	var members=data.cluster && data.cluster.members || [];
	var descriptions={recovery_unavailable:_('Recovery service is unavailable; configuration changes are blocked.'),
		bus_unavailable:_('Local service status cannot be read.'),node_offline:_('No recent authenticated node report.'),
		agent_unavailable:_('The node agent has not reported a fresh status.'),
		agent_check_failed:_('The node agent check failed. Inspect the system logs.'),
		backhaul_unavailable:_('No active backhaul path was reported.'),backup_active:_('Wireless backup is active. Check the preferred wired connection.')};
	var destinations={nodes:_('View node'),backhaul:_('View backhaul'),diagnostics:_('View diagnostics')};
	return widgets.section(_('Needs attention'),[
		widgets.pagedTable('current-attention',[_('Node'),_('Issue'),_('Action')],state.items || [],function(row){
			var node=members.find(function(member){return member.id===row.node_id;});
			var message=row.code==='configuration_drift'?_('Managed configuration differs in %s fields. Preview a repair on the Nodes page.').format(row.count):descriptions[row.code] || _('Unknown');
			return [row.node_id ? node && node.name || _('AP node') : _('This device'),widgets.status(message,row.severity),
				destinations[row.page] ? E('a',{href:L.url('admin','network','mesh-manager',row.page)},[destinations[row.page]]) : '-'];
		},_('No current alerts')),
		state.total ? E('p',{'class':'mm-muted'},[_('Current observations only. Alerts disappear after recovery; past failures remain in Changes.')]) : null,
		state.truncated ? E('p',{'class':'mm-error'},[_('Only the first 128 alerts are shown. Check the Nodes page for the remaining devices.')]) : null
	]);
},active:function(data,canWrite,group){
	writable=canWrite;
	if(group!=='wireless' && !probeSection){
		probeTarget=E('select',{'class':'cbi-input-select mm-probe-target','aria-label':_('Diagnostic node')});
		probeStart=button(_('Check connectivity'),function(){return runProbe('node_ping');});
		probeTrace=button(_('Trace node path'),function(){return runProbe('node_trace');});
		probeDns=button(_('Check local DNS'),function(){return runProbe('local_dns');});
		probeUpstream=button(_('Check runtime DNS candidates'),function(){return runProbe('local_upstream_dns');});
		probeAddress=button(_('Check local address conflict'),function(){return runProbe('local_address_conflict');});
		[[probeStart,_('Sends three ICMP packets to the selected managed node, for at most five seconds. ICMP can be blocked by a firewall; this does not verify device identity, service health or roaming.')],
		 [probeTrace,_('Path tracing sends one UDP probe per hop, up to five hops with a one-second wait each. Missing replies can result from filtering and do not prove a node is offline.')],
		 [probeDns,_('The local DNS check asks this device for the localhost A record, with a two-second DNS wait. No DNS server or network configuration is changed.')],
		 [probeUpstream,_('The runtime DNS check sends one root NS query to each of at most four netifd IPv4 DNS candidates. It preserves DNS and network settings.')],
		 [probeAddress,_('The local address check sends two ARP probes for this device’s current primary LAN IPv4, within three seconds. It does not change addresses or scan other nodes.')]
		].forEach(function(row){row[0].setAttribute('data-tooltip',row[1]);row[0].setAttribute('aria-description',row[1]);});
		probeCancel=button(_('Cancel check'),function(){if(probeControl && probeControl.cancel)probeControl.cancel().catch(function(error){probeOutput.textContent=probeFailure(error);});});
		probeCancel.disabled=true;probeOutput=E('div',{role:'status','aria-live':'polite','class':'mm-probe-result'});
		probeSection=widgets.section(_('Node connectivity'),[
			E('div',{'class':'mm-actions'},[probeTarget,probeStart,probeTrace,probeDns,probeUpstream,probeAddress,probeCancel]),probeOutput
		]);
	}
	if(group!=='wireless' && !probeRunning){
		var identity=data.cluster && data.cluster.identity,targets=[];
		probeLocalId=identity && identity.id;
		if(data.mesh_enabled && identity && identity.role==='root')targets=(data.cluster.members || []).filter(function(node){return node.authorized && node.online && !node.mesh_paused;});
		else if(data.mesh_enabled && identity && identity.role==='ap' && identity.controller_id)targets=[{id:identity.controller_id,name:_('Controller')}];
		var selected=probeTarget.value;
		probeTarget.replaceChildren.apply(probeTarget,targets.length?targets.map(function(node){return E('option',{value:node.id},[node.name || node.id]);}):[E('option',{value:''},[_('No online managed nodes')])]);
		if(targets.some(function(node){return node.id===selected;}))probeTarget.value=selected;
	}
	var wireless=group==='network'?[]:[radioCapabilities(data),regulatoryData(data)];updateChecks();
	return {connectivity:probeSection,wireless:wireless};
}});
