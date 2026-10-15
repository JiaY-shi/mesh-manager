// SPDX-License-Identifier: GPL-2.0-only
'use strict';

// A running shared DNS daemon is insufficient: confirmation must find the
// requested business pool in the configuration its actual instance uses.
export function business_dhcp_ready(id, subnet, snapshot, instances, read) {
 if(id!='guest' || !match(subnet || '',/^[0-9.]+\.1\/24$/))return false;
 let configs=filter(keys(snapshot.dhcp || {}),n=>snapshot.dhcp[n].type=='dnsmasq' && match(n,/^[a-zA-Z0-9_]{1,64}$/)),
     prefix=join('.',slice(split(split(subnet,'/')[0],'.'),0,3)),
     range='dhcp-range=set:mm_'+id+','+prefix+'.100,'+prefix+'.199,255.255.255.0,2h';
 for(let name in configs) {
  let path='/var/etc/dnsmasq.conf.'+name,instance=instances?.[name],command=instance?.command;
  if(instance?.running!==true || type(command)!='array' || command[0]!='/usr/sbin/dnsmasq')continue;
  let argument=index(command,'-C');if(argument<0 || command[argument+1]!=path)continue;
  let raw=read(path);
  if(type(raw)=='string' && length(raw)<=131072 && index(raw,'\0')<0 &&
   length(filter(split(raw,'\n'),line=>line==range))==1)return true;
 }
 return false;
}
