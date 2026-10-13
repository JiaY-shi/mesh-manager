// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';

export const FEATURE_CACHE='/var/run/mesh-manager-wireless-features.json';
export const FEATURE_PATHS=['/usr/sbin/hostapd','/usr/sbin/wpa_supplicant','/usr/share/hostap/wpa_supplicant.uc'];
const NAMES=['sae','ft','mesh'],TTL=300000,LIMIT=4096;
function equal(a,b) { return sprintf('%J',a)==sprintf('%J',b); }
function fields(value,names) {return type(value)=='object' && length(keys(value))==length(names) &&
	!length(filter(keys(value),name=>index(names,name)<0));}
export function feature_boot() {let value=trim(fs.readfile('/proc/sys/kernel/random/boot_id') || '');
	if(!match(value,/^[0-9a-f-]{36}$/))die('clock_error: Wireless feature boot unavailable');return value;}
export function feature_now() {let value=fs.readfile('/proc/uptime');
	if(!match(value || '',/^[0-9]+\.[0-9]+ /))die('clock_error: Wireless feature clock unavailable');return int(+split(value,' ')[0]*1000);}
function stamp(value) {if(!value)return null;let out={};
	for(let key in ['type','dev','inode','mode','uid','gid','nlink','size','mtime','ctime'])out[key]=value[key];return out;}
export function feature_signature() {
	return map(FEATURE_PATHS,path=>{
		let link=fs.lstat(path),target=fs.stat(path),link_value=link?.type=='link'?fs.readlink(path):null;
		if(link && (index(['file','link'],link.type)<0 || link.uid!=0 || link.mode&0022 && link.type!='link') ||
			target && (target.type!='file' || target.uid!=0 || target.mode&0022 || target.nlink<1) ||
			link?.type=='link' && (type(link_value)!='string' || length(link_value)>256) || link && !target)
			die('storage_error: Unsafe wireless feature artifact');
		return {path,link:stamp(link),target:stamp(target),link_value};
	});
}
export function valid_signature(value) {
	if(type(value)!='array' || length(value)!=3)return false;
	for(let i=0;i<3;i++) {
		let row=value[i];if(!fields(row,['path','link','target','link_value']) || row.path!=FEATURE_PATHS[i])return false;
		if(row.link==null) {if(row.target!=null || row.link_value!=null)return false;continue;}
		for(let key in ['link','target']) {
			let item=row[key];if(!fields(item,['type','dev','inode','mode','uid','gid','nlink','size','mtime','ctime']) ||
				index(key=='link'?['file','link']:['file'],item.type)<0 || item.uid!==0 || item.nlink<1)return false;
			if(!fields(item.dev,['major','minor']) || type(item.dev.major)!='int' || item.dev.major<0 ||
				type(item.dev.minor)!='int' || item.dev.minor<0)return false;
			for(let field in ['inode','mode','uid','gid','nlink','size','mtime','ctime'])
				if(type(item[field])!='int' || item[field]<0)return false;
			if(item.type=='file' && item.mode&0022)return false;
		}
		if(row.link.type=='link' ? type(row.link_value)!='string' || length(row.link_value)>256 : row.link_value!=null)return false;
	}
	return true;
}
function features_valid(features) {
	if(!fields(features,NAMES))return false;
	for(let name in NAMES) {
		let item=features[name];if(!fields(item,['supported','status']) || index(['supported','unsupported','missing','timeout','probe_failed'],item.status)<0)return false;
		if(item.status=='supported' ? item.supported!==true : index(['unsupported','missing'],item.status)>=0 ?
			item.supported!==false : item.supported!==null)return false;
	}
	return true;
}
function unknown(status) {let out={};for(let name in NAMES)out[name]={supported:null,status:status || 'probe_failed'};return out;}
export function feature_probe(run,signature) {
	if(!valid_signature(signature))die('invalid_request: Wireless feature signature invalid');
	let out={};
	for(let i=0;i<3;i++) {
		let name=NAMES[i],binary=i<2?signature[0]:signature[1],result=binary.target?
			run([FEATURE_PATHS[i<2?0:1],['-vsae','-v11r','-vmesh'][i]],'',3000):null;
		out[name]=!binary.target?{supported:false,status:'missing'}:result?.code===0?{supported:true,status:'supported'}:
			result?.code===1?{supported:false,status:'unsupported'}:{supported:null,status:result?.code===-2?'timeout':'probe_failed'};
	}
	return out;
}
export function feature_worker(run,input,io) {
	io ||= {signature:feature_signature,boot:feature_boot};
	if(!fields(input,['schema','boot','signature']) || input.schema!==1 || input.boot!=io.boot() ||
		!valid_signature(input.signature) || !equal(input.signature,io.signature()))die('preview_changed: Wireless feature input changed');
	let features=feature_probe(run,input.signature);
	if(input.boot!=io.boot() || !equal(input.signature,io.signature()))die('preview_changed: Wireless feature artifacts changed');
	return {schema:1,boot:input.boot,signature:input.signature,features};
}
function safe(st,empty) {return st?.type=='file' && st.uid==0 && (st.mode&07777)==0600 && st.nlink==1 && st.size>=(empty?0:1) && st.size<=LIMIT;}
function frame_at(path,empty,io) {
	io ||= fs;
	let st=io.lstat(path);if(!st)return {present:false,raw:null,stamp:null,safe:true};
	if(!safe(st,empty))return {present:true,raw:null,stamp:stamp(st),safe:false};
	// O_RDWR prevents a concurrent FIFO replacement blocking open on Linux. No writes
	// are issued; only the unchanged regular descriptor can be read below.
	let file=io.open(path,'r+e'),opened=file?io.stat('/proc/self/fd/'+file.fileno()):null,path_open=io.lstat(path),raw=null,after_open=null;
	if(file && safe(opened,empty) && safe(path_open,empty) && equal(stamp(st),stamp(opened)) && equal(stamp(st),stamp(path_open))) {raw=file.read(LIMIT+1);after_open=io.stat('/proc/self/fd/'+file.fileno());}
	file?.close();let after=io.lstat(path);
	return type(raw)=='string' && length(raw)==st.size && equal(stamp(st),stamp(after_open)) && equal(stamp(st),stamp(after))?
		{present:true,raw,stamp:stamp(st),safe:true}:{present:true,raw:null,stamp:stamp(after),safe:false};
}
export function feature_cache_frame(io) {return frame_at(FEATURE_CACHE,false,io);}
export function cache_shape(frame) {
	let value;
	if(!frame.safe || type(frame.raw)!='string' || length(frame.raw)>LIMIT)return null;
	try {value=json(frame.raw);}catch(e){return null;}
	if(!fields(value,['schema','boot','signature','observed','failures','next_probe','features']) || value.schema!==1 ||
		type(value.boot)!='string' || !match(value.boot,/^[0-9a-f-]{36}$/) || !valid_signature(value.signature) ||
		type(value.observed)!='int' || value.observed<0 ||
		type(value.failures)!='int' || value.failures<0 || value.failures>4 ||
		type(value.next_probe)!='int' || value.next_probe<value.observed || value.next_probe>value.observed+TTL ||
		!features_valid(value.features))return null;
	let complete=!length(filter(NAMES,name=>value.features[name].supported==null));
	if(complete && (value.failures!=0 || value.next_probe!=value.observed+TTL) ||
		!complete && (value.failures<1 || value.next_probe!=value.observed+[30000,60000,120000,300000][value.failures-1]))return null;
	return value;
}
export function cache_value(frame,signature,boot,now) {
	let value=cache_shape(frame);
	return value && value.boot==boot && value.observed<=now && equal(value.signature,signature)?value:null;
}
export function feature_projection(frame,signature,boot,now) {
	let value=valid_signature(signature)?cache_value(frame,signature,boot,now):null;
	let fresh=value && now<value.observed+TTL;
	let state=!frame.safe?'unknown':!frame.present?'pending':!value?'unknown':!fresh?'pending':
		length(filter(NAMES,name=>value.features[name].supported==null))?'unavailable':'ready';
	let features=fresh?value.features:unknown(),out={wireless_features_state:state,wireless_probe_errors:[]};
	for(let name in NAMES) {out[name]=features[name].supported;if(out[name]==null)push(out.wireless_probe_errors,name);}
	return out;
}
export function cached_wireless_features() {
	try {let signature=feature_signature(),frame=feature_cache_frame(),boot=feature_boot(),now=feature_now();
		if(!equal(signature,feature_signature()) || boot!=feature_boot())return {sae:null,ft:null,mesh:null,
			wireless_features_state:'unknown',wireless_probe_errors:NAMES};
		return feature_projection(frame,signature,boot,now);
	} catch(e) {return {sae:null,ft:null,mesh:null,wireless_features_state:'unknown',wireless_probe_errors:NAMES};}
}
export function publish_feature_cache(value,expected,io) {
	io ||= fs;
	let content=sprintf('%J',value),directory,path,file,opened,created,dir_stamp,result=false;
	if(length(content)>LIMIT || !cache_shape({safe:true,raw:content}) || !expected.safe ||
		expected.present && !cache_shape(expected) || !equal(expected,feature_cache_frame(io)))return false;
	function cleanup() {
		file?.close();file=null;
		// Remove only our unchanged private inode and bytes; keep foreign replacements.
		let current=path?frame_at(path,true,io):null;
		if(current?.safe && current.present && created?.present && opened && equal(current,created) && equal(current.stamp.dev,opened?.dev) &&
			current.stamp.inode==opened?.inode)io.unlink(path);
		let dir=directory?stamp(io.lstat(directory)):null;
		if(dir?.type=='directory' && dir.uid==0 && dir.mode==dir_stamp?.mode &&
			equal(dir.dev,dir_stamp?.dev) && dir.inode==dir_stamp?.inode)io.rmdir(directory);
	}
	try {
		directory=io.mkdtemp('/var/run/mesh-manager-feature-stage.XXXXXX');
		dir_stamp=stamp(io.lstat(directory));
		if(dir_stamp?.type!='directory' || dir_stamp.uid!=0 || dir_stamp.mode&0077)die('storage_error: Unsafe feature staging directory');
		path=directory+'/value';file=io.open(path,'wx',0600);
		opened=file?stamp(io.stat('/proc/self/fd/'+file.fileno())):null;
		if(!opened || !equal(opened,stamp(io.lstat(path))) || !safe(io.lstat(path),true))die('storage_error: Cannot create feature staging');
		let written=file.write(content),flushed=file.flush();file.close();file=null;created=frame_at(path,true,io);
		if(written!=length(content) || !flushed || !created.safe || created.raw!=content ||
			!equal(created.stamp.dev,opened.dev) || created.stamp.inode!=opened.inode ||
			!equal(created,frame_at(path,true,io)) || !equal(expected,feature_cache_frame(io)) ||
			value.boot!=feature_boot() || !equal(value.signature,feature_signature()))die('preview_changed: Feature publication changed');
		if(!io.rename(path,FEATURE_CACHE))die('storage_error: Cannot publish feature cache');
		path=null;result=true;
	} catch(e) {
		// Snapshot a partial write only through the descriptor's original inode.
		file?.close();file=null;
		if(path && opened && !created) {
			let partial=frame_at(path,true,io);
			if(partial.safe && equal(partial.stamp.dev,opened.dev) && partial.stamp.inode==opened.inode &&
				index(content,partial.raw)==0)created=partial;
		}
	}
	cleanup();return result;
}
export function feature_controller(io) {
	let active=null,generation=0,stopped=false,retry_after=0,failures=0;
	function fail(now) {failures=min(4,failures+1);retry_after=max(retry_after,now+[30000,60000,120000,300000][failures-1]);}
	function cancel() {if(active && !active.cancelled) {active.cancelled=true;generation++;
		active.worker?.cancel();let clock=active.started;try {let current=io.now();if(type(current)=='int' && current>=clock)clock=current;}catch(e){}
		retry_after=max(retry_after,clock+30000);}}
	function tick(pending) {
		if(stopped)return;
		if(pending!==false) {cancel();return;}
		if(active)return;
		let now;try {now=io.now();}catch(e){return;}if(type(now)!='int' || now<0 || now<retry_after)return;
		let signature,frame,boot,value,shape;
		try {signature=io.signature();boot=io.boot();frame=io.read();shape=cache_shape(frame);
			if(!valid_signature(signature) || !frame.safe || frame.present && !shape || shape?.boot==boot && shape.observed>now) {fail(now);return;}
			// Retry failures globally, including after an artifact changes or daemon restart.
			if(shape && shape.boot==boot && shape.observed<=now && shape.failures>0) {
				failures=max(failures,shape.failures);retry_after=max(retry_after,shape.next_probe);
				if(now<retry_after)return;
			}
			value=cache_value(frame,signature,boot,now);
			if(value && !value.failures && now<value.next_probe)return;
		} catch(e) {fail(now);return;}
		let attempt={generation:++generation,signature,frame,boot,started:now,cancelled:false,worker:null};active=attempt;
		try {
			attempt.worker=io.spawn({schema:1,boot,signature},12000,result=>{
				if(active!==attempt)return;
				active=null;
				if(stopped || attempt.cancelled || generation!=attempt.generation)return;
				let done,reply;try {done=io.now();}catch(e){retry_after=max(retry_after,attempt.started+30000);return;}
				if(type(done)!='int' || done<attempt.started) {retry_after=max(retry_after,attempt.started+30000);return;}
				try {
					if(io.pending()!==false || boot!=io.boot() || !equal(signature,io.signature())) {retry_after=max(retry_after,done+30000);return;}
					if(result?.code===0 && type(result.stdout)=='string' && length(result.stdout)<=LIMIT)try {reply=json(result.stdout);}catch(e){}
					if(!fields(reply,['schema','boot','signature','features']) || reply.schema!==1 || reply.boot!=boot ||
						!equal(reply.signature,signature) || !features_valid(reply.features))reply={features:unknown(result?.code===-2?'timeout':'probe_failed')};
					let complete=!length(filter(NAMES,name=>reply.features[name].supported==null));
					let next=done+TTL,prior_failures=failures;
					if(complete)failures=0;else {fail(done);next=retry_after;}
					let cache={schema:1,boot,signature,observed:done,failures,next_probe:next,features:reply.features};
					if(!io.publish(cache,frame) && complete) {failures=prior_failures;fail(done);}
				} catch(e) {fail(done);}
			});
			if(!attempt.worker) {active=null;fail(now);}
		} catch(e) {active=null;fail(now);}
	}
	return {tick,stop:()=>{stopped=true;cancel();},pending:()=>active!=null};
}
