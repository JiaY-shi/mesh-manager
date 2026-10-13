// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import * as fs from 'fs';
import { now, boot } from './durable.uc';
import { equal } from './model.uc';

const CONTACT='/var/run/mesh-manager-controller-contact.json';
const WATCH='/var/run/mesh-manager-controller-watch.json';
export function contact_binding(binding) {
	return {controller_id:binding?.controller_id,network_id:binding?.network_id,ca_fingerprint:binding?.ca_fingerprint};
}

export function contact_read(watch) {
	let path=watch === true ? WATCH : CONTACT, st=fs.lstat(path);
	if (!st) return null;
	if (st.type!='file' || st.uid!=0 || st.mode&0077 || st.size>1024 || st.nlink!=1)
		die('storage_error: Unsafe controller recovery observation');
	let raw=fs.readfile(path);
	if (type(raw)!='string' || length(raw)!=st.size) die('storage_error: Incomplete controller recovery observation');
	try {return json(raw);} catch(e) {die('storage_error: Invalid controller recovery observation');}
}
export function contact_write(value, watch) {
	let target=watch === true ? WATCH : CONTACT;
	contact_read(watch);
	let text=sprintf('%J',value);
	if (length(text)>1024) die('storage_error: Controller recovery observation is oversized');
	let directory=fs.mkdtemp('/var/run/mesh-manager-contact.XXXXXX');
	if (!directory) die('storage_error: Cannot prepare controller recovery observation');
	let path=directory+'/value',file;
	try {
		file=fs.open(path,'we',0600);
		let complete=file?.write(text)==length(text) && file.flush();file?.close();file=null;
		if (!complete || !fs.rename(path,target)) die('storage_error: Cannot publish controller recovery observation');
		fs.rmdir(directory);
	} catch(e) {file?.close();fs.unlink(path);fs.rmdir(directory);die(e.message || ''+e);}
}
export function record_contact(binding) {
	// Called only after mTLS and the actual response/nonce have been verified.
	// This observation never authorizes a configuration or writes flash.
	try {
		binding=contact_binding(binding);
		let clock=now(),id=boot(),prior=contact_read();
		if (prior?.boot==id && equal(prior.binding,binding) && clock>=prior.uptime && clock-prior.uptime<2) return;
		contact_write({boot:id,binding,uptime:clock});
	} catch(e) {
		// A full tmpfs must not invalidate an otherwise authenticated exchange.
		// The independent monitor reports the storage fault before changing UCI.
	}
}
