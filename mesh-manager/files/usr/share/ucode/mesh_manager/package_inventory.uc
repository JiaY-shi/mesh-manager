// SPDX-License-Identifier: GPL-2.0-only
'use strict';
import { valid_text } from './model.uc';

const groups = [
	['mesh-manager'], ['luci-app-mesh-manager'], ['busybox'], ['ucode'], ['rpcd'], ['rpcd-mod-ucode'],
	['netifd'], ['procd'], ['ip-full'], ['ip-bridge'], ['umdns'], ['usteer'], ['firewall4'],
	['dnsmasq','dnsmasq-full'], ['odhcpd','odhcpd-ipv6only'],
	['wpad','wpad-openssl','wpad-wolfssl','wpad-mbedtls','wpad-mesh-openssl','wpad-mesh-wolfssl','wpad-mesh-mbedtls',
		'wpad-basic-openssl','wpad-basic-wolfssl','wpad-basic-mbedtls','wpad-mini','hostapd-openssl','hostapd-wolfssl','hostapd-mbedtls'],
	['libiwinfo'], ['ucode-mod-nl80211']
];
function names() { let result=[];for(let group in groups)for(let name in group)push(result,name);return result; }
function iwinfo_name(name) {
	if(name=='libiwinfo')return true;
	if(type(name)!='string' || length(name)!=17 || substr(name,0,9)!='libiwinfo')return false;
	for(let i=9;i<17;i++)if(ord(name,i)<48 || ord(name,i)>57)return false;
	return true;
}
function invalid() { die('backend_unavailable: Installed package metadata is unavailable'); }
export function package_result(result, backend) {
	if (result?.code==-2) die('request_timeout: Package inspection exceeded its deadline');
	if (result?.code!=0 || type(result.stdout)!='string' || length(result.stdout)>65536 ||
		index(result.stdout,'\u0000')>=0 || match(result.stdout,/[^\n -~]/) || index(['apk','opkg'],backend)<0) invalid();
	let wanted=names(),found={},seen={};
	for(let line in split(trim(result.stdout),'\n')) {
		if(!length(line))continue;
		let fields=split(line,backend=='apk'?' ':' - '),name=fields[0],version=fields[1];
		if(length(fields)!=2 || !valid_text(name,1,64,true) || !match(name,/^[a-z0-9][a-z0-9+_.-]*$/) ||
			!valid_text(version,1,96,true) || index(version,' ')>=0 || seen[name]) invalid();
		seen[name]=true;
		if(index(wanted,name)>=0 || iwinfo_name(name)) found[name]=version;
	}
	return {backend,items:map(groups,group=>{
		let installed=group[0]=='libiwinfo' ? sort(filter(keys(found),iwinfo_name)) : filter(group,name=>found[name]!=null);
		return {name:group[0]=='wpad'?'hostapd/wpad':group[0],status:length(installed)?'installed':'not_installed',
			packages:map(installed,name=>({name,version:found[name]}))};
	})};
}
export function package_inventory(args, io) {
	if(type(args)!='object' || length(keys(args)))die('invalid_request: Package inspection accepts no package names or options');
	let backend,argv;
	if(io.executable('/usr/bin/apk')) {
		backend='apk';argv=['/usr/bin/apk','list','--installed','--manifest','--no-network','--no-logfile','--repositories-file','/dev/null',...map(names(),name=>name=='libiwinfo'?'libiwinfo*':name)];
	} else if(io.executable('/bin/opkg')) {backend='opkg';argv=['/bin/opkg','list-installed'];}
	else if(io.executable('/usr/bin/opkg')) {backend='opkg';argv=['/usr/bin/opkg','list-installed'];}
	else invalid();
	return {...package_result(io.run(argv,'',3000),backend),observed_at:io.time()};
}
