// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <ucode/module.h>

#ifndef MESH_ONBOARD_ROOT
#define MESH_ONBOARD_ROOT "/var/run"
#endif
#ifndef MESH_ONBOARD_DURABLE
#define MESH_ONBOARD_DURABLE "/etc/mesh-manager"
#endif
#ifndef MESH_ONBOARD_UID
#define MESH_ONBOARD_UID 0
#endif
#define DIRECTORY "mesh-manager-onboard"
#define IFACE "mm-onboard"
#define STATE "state.json"
#define STAGE "state.new"
#define CONFIG "wpa.conf"
#define CONTROL "control"
#define LIMIT 8192
#define PERMIT_LIMIT 4096
#define JOURNAL_LIMIT (256 * 1024)
#define RAW_LIMIT (1024 * 1024)
#define RETRIES 8
#define LIFETIME 900000
#define SETUP 60000
#define FRESH 6500
#define WORKER "/usr/libexec/mesh-manager-onboard-worker"
#define DHCP "/usr/libexec/mesh-manager-onboard-dhcp"
// BusyBox udhcpc replaces descriptors 3 and 4 with its signal pipe.
// Keep the private lease capability separate from those descriptors.
#define LEASE_FD 9

struct actor {
 int dir, control, pending, permit_fd;
 pid_t wpa, dhcp;
 bool wpa_reaped, dhcp_reaped, addr_created, route_created, lost, link_requested, setup_complete, cleaning, address_conflict;
 int ifindex, phy;
 unsigned char mac[6];
 struct in_addr controller, lease;
 uint64_t deadline, setup_deadline, lease_deadline, cleanup_deadline;
 char generation[33], boot[37], owner_start[21], origin_tag[65];
 char *last_raw, *permit_raw;
 struct stat dir_stat, state_stat, config_stat, socket_stat;
 char *inventory;
 bool state_exists, config_exists, socket_exists, discover;
};

static uint64_t clock_ms(void) {
 struct timespec ts;
 if(clock_gettime(CLOCK_MONOTONIC,&ts))return 0;
 return (uint64_t)ts.tv_sec*1000+ts.tv_nsec/1000000;
}
static uint64_t budget(struct actor *a,unsigned milliseconds) {
 uint64_t now=clock_ms(),end=a->cleaning ? a->cleanup_deadline : a->setup_complete ? a->deadline : a->setup_deadline;
 if(now>=end)return now;
 return end-now<milliseconds ? end : now+milliseconds;
}
static bool same_stat(const struct stat *a,const struct stat *b) {
 return a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_size==b->st_size &&
  a->st_mtim.tv_sec==b->st_mtim.tv_sec && a->st_mtim.tv_nsec==b->st_mtim.tv_nsec &&
  a->st_ctim.tv_sec==b->st_ctim.tv_sec && a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static bool safe_stat(const struct stat *s,bool dir) {
 return s->st_uid==MESH_ONBOARD_UID && !(s->st_mode&0077) &&
  (dir ? S_ISDIR(s->st_mode) : S_ISREG(s->st_mode) && s->st_nlink==1);
}
static bool path_same(int dir,const char *name,const struct stat *st,bool absent) {
 struct stat now;
 int result=fstatat(dir,name,&now,AT_SYMLINK_NOFOLLOW);
 return absent ? result<0 && errno==ENOENT : !result && same_stat(st,&now);
}
static bool directory_same(int dir) {
 int p=open(MESH_ONBOARD_ROOT,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
 struct stat a,b,parent;
 bool ok=p>=0 && !fstat(p,&parent) && S_ISDIR(parent.st_mode) && parent.st_uid==MESH_ONBOARD_UID &&
  !(parent.st_mode&0022) && !fstat(dir,&a) && safe_stat(&a,true) &&
  !fstatat(p,DIRECTORY,&b,AT_SYMLINK_NOFOLLOW) && a.st_dev==b.st_dev && a.st_ino==b.st_ino;
 if(p>=0)close(p);
 return ok;
}
static int open_directory(bool *missing) {
 *missing=false;
 int p=open(MESH_ONBOARD_ROOT,O_RDONLY|O_DIRECTORY|O_CLOEXEC),dir=-1;
 struct stat st;
 if(p<0 || fstat(p,&st) || !S_ISDIR(st.st_mode) || st.st_uid!=MESH_ONBOARD_UID || st.st_mode&0022)goto done;
 dir=openat(p,DIRECTORY,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 *missing=dir<0 && errno==ENOENT;
 if(dir>=0 && !directory_same(dir)){close(dir);dir=-1;}
 done:if(p>=0)close(p);return dir;
}
static char *read_file(int dir,const char *name,size_t maximum,struct stat *saved) {
 int fd=openat(dir,name,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
 struct stat a,b;char *raw=NULL,extra;size_t used=0;unsigned retry=0;
 if(fd<0 || fstat(fd,&a) || !safe_stat(&a,false) || a.st_size<1 || a.st_size>(off_t)maximum)goto done;
 raw=malloc((size_t)a.st_size+1);if(!raw)goto done;
 while(used<(size_t)a.st_size) {
  ssize_t n=read(fd,raw+used,(size_t)a.st_size-used);
  if(n<0 && errno==EINTR && retry++<RETRIES)continue;
  if(n<=0)goto fail;
  used+=(size_t)n;
 }
 ssize_t n;retry=0;
 do{n=read(fd,&extra,1);}while(n<0 && errno==EINTR && retry++<RETRIES);
 if(n!=0 || fstat(fd,&b) || !safe_stat(&b,false) || !same_stat(&a,&b) ||
  !path_same(dir,name,&b,false) || memchr(raw,0,used))goto fail;
 raw[used]=0;if(saved)*saved=b;goto done;
 fail:free(raw);raw=NULL;
 done:if(fd>=0 && close(fd)){free(raw);raw=NULL;}return raw;
}
static bool write_all(int fd,const char *raw,size_t size,uint64_t deadline) {
 size_t used=0;unsigned retry=0;
 while(used<size && clock_ms()<deadline) {
  ssize_t n=send(fd,raw+used,size-used,MSG_NOSIGNAL);
  if(n<0 && errno==ENOTSOCK)n=write(fd,raw+used,size-used);
  if(n<0 && errno==EINTR && retry++<RETRIES)continue;
  if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)){
   uint64_t now=clock_ms();if(now>=deadline)return false;
   struct pollfd p={.fd=fd,.events=POLLOUT};if(poll(&p,1,(int)(deadline-now))<=0)return false;continue;
  }
  if(n<=0)return false;
  used+=(size_t)n;
 }
 return used==size && clock_ms()<deadline;
}
static bool boot_id(char output[37]) {
 int fd=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC);char buf[38]={0};
 ssize_t n=fd<0 ? -1 : read(fd,buf,37);if(fd>=0)close(fd);
 if(n!=37 || buf[36]!='\n')return false;
 for(size_t i=0;i<36;i++)if(i==8 || i==13 || i==18 || i==23){if(buf[i]!='-')return false;}
  else if(!((buf[i]>='a' && buf[i]<='f') || (buf[i]>='0' && buf[i]<='9')))return false;
 memcpy(output,buf,36);output[36]=0;return true;
}
static bool process_start(pid_t pid,char output[21]) {
 char path[64],buf[2048];snprintf(path,sizeof(path),"/proc/%ld/stat",(long)pid);
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NONBLOCK);ssize_t n=fd<0 ? -1 : read(fd,buf,sizeof(buf)-1);
 if(fd>=0)close(fd);
 if(n<=0 || n==(ssize_t)sizeof(buf)-1)return false;
 buf[n]=0;char *end=strrchr(buf,')');if(!end || end[1]!=' ' || end[2]=='Z' || end[2]=='X')return false;
 char *next=end+2,*save=NULL,*field=NULL;
 for(unsigned i=3;i<=22;i++){field=strtok_r(i==3 ? next : NULL," ",&save);if(!field)return false;}
 size_t len=strlen(field);if(!len || len>20 || strspn(field,"0123456789")!=len)return false;
 memcpy(output,field,len+1);return true;
}
static bool entropy(unsigned char *buf,size_t size) {
 size_t used=0;unsigned retry=0;uint64_t deadline=clock_ms()+250;
 while(used<size && clock_ms()<deadline){ssize_t n=getrandom(buf+used,size-used,GRND_NONBLOCK);
  if(n<0 && errno==EINTR && retry++<RETRIES)continue;
  if(n<=0)return false;
  used+=(size_t)n;}
 return used==size && clock_ms()<deadline;
}
static bool hash_parts(char output[65],const char *a,const char *b,const char *c) {
 EVP_MD_CTX *ctx=EVP_MD_CTX_new();unsigned char digest[32];unsigned length=0;
 bool ok=ctx && EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)==1;
 const char *parts[]={a,b,c};
 for(size_t i=0;ok && i<3;i++){uint64_t size=parts[i]?strlen(parts[i]):0;
  unsigned char prefix[8];for(unsigned j=0;j<8;j++)prefix[j]=(unsigned char)(size>>(j*8));
  ok=EVP_DigestUpdate(ctx,prefix,8)==1 && (!size || EVP_DigestUpdate(ctx,parts[i],size)==1);}
 if(ok)ok=EVP_DigestFinal_ex(ctx,digest,&length)==1 && length==32;
 EVP_MD_CTX_free(ctx);
 if(!ok)return false;
 for(unsigned i=0;i<32;i++)snprintf(output+2*i,3,"%02x",digest[i]);
 return true;
}
static json_object *parse_json(const char *raw) {
 if(!raw || !*raw)return NULL;
 size_t len=strlen(raw);
 struct json_tokener *t=json_tokener_new_ex(32);if(!t)return NULL;
 json_object *o=json_tokener_parse_ex(t,raw,(int)len);
 bool ok=json_tokener_get_error(t)==json_tokener_success;size_t end=json_tokener_get_parse_end(t);
 while(end<len && (raw[end]==' ' || raw[end]=='\r' || raw[end]=='\n' || raw[end]=='\t'))end++;
 ok=ok && end==len && o && json_object_get_type(o)==json_type_object;json_tokener_free(t);
 if(!ok){json_object_put(o);return NULL;}return o;
}
static uc_value_t *failure(uc_vm_t *vm,const char *code) {
 uc_value_t *o=ucv_object_new(vm);ucv_object_add(o,"error",ucv_string_new(code));return o;
}
static const char *text_field(uc_value_t *object,const char *key,size_t maximum) {
 uc_value_t *v=ucv_object_get(object,key,NULL);
 if(ucv_type(v)!=UC_STRING || !ucv_string_length(v) || ucv_string_length(v)>maximum ||
  memchr(ucv_string_get(v),0,ucv_string_length(v)))return NULL;
 // ucode packs short strings into the value word. Its getter then returns a
 // pointer into this local variable, which cannot escape this helper. Promote
 // the identical value into object-owned heap storage before returning it.
 if(((uintptr_t)v&3)==UC_STRING) {
  char *text=NULL;size_t length=ucv_string_length(v);uc_value_t *heap=ucv_string_alloc(&text,length);
  memcpy(text,ucv_string_get(v),length);text[length]=0;
  if(!ucv_object_add(object,key,heap)){ucv_put(heap);return NULL;}v=heap;
 }
 return ucv_string_get(v);
}
static bool number_field(uc_value_t *o,const char *key,int64_t minimum,int64_t maximum,int64_t *out) {
 uc_value_t *v=ucv_object_get(o,key,NULL);if(ucv_type(v)!=UC_INTEGER)return false;
 int64_t n=ucv_int64_get(v);if(n<minimum || n>maximum)return false;*out=n;return true;
}
static uc_value_t *scope_read(uc_vm_t *vm,size_t nargs) {
 if(nargs)return failure(vm,"runtime_unavailable");
 const char *files[]={"identity.json","device.key","join-ca.crt","network-ca.crt","device.crt"};
 const char *fields[]={"identity","key","join_ca","network_ca","cert"};
 int dir=open(MESH_ONBOARD_DURABLE,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 struct stat parent,path,st[5];bool missing[5]={0};char *raw[5]={0},boot[37],tag[65];uc_value_t *result=NULL;
 if(dir<0 || fstat(dir,&parent) || !safe_stat(&parent,true))goto done;
 for(unsigned i=0;i<5;i++) {
  raw[i]=read_file(dir,files[i],i<2 ? RAW_LIMIT : LIMIT,&st[i]);
  if(!raw[i]) {missing[i]=fstatat(dir,files[i],&path,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT;
   if(i<2 || !missing[i])goto done;}
 }
 for(unsigned i=0;i<5;i++)if(!path_same(dir,files[i],&st[i],missing[i]))goto done;
 if(lstat(MESH_ONBOARD_DURABLE,&path) || parent.st_dev!=path.st_dev || parent.st_ino!=path.st_ino || !boot_id(boot))goto done;
 result=ucv_object_new(vm);
 for(unsigned i=0;i<5;i++)ucv_object_add(result,fields[i],raw[i] ? ucv_string_new(raw[i]) : NULL);
 ucv_object_add(result,"boot",ucv_string_new(boot));
 char signature[1024];size_t used=0;
 for(unsigned i=0;i<5;i++) {
  int n=snprintf(signature+used,sizeof(signature)-used,"%u:%d:%llu:%llu:%lld:%lld:%ld:%lld:%ld;",i,missing[i],
   missing[i] ? 0ULL : (unsigned long long)st[i].st_dev,missing[i] ? 0ULL : (unsigned long long)st[i].st_ino,
   missing[i] ? 0LL : (long long)st[i].st_size,missing[i] ? 0LL : (long long)st[i].st_mtim.tv_sec,
   missing[i] ? 0L : st[i].st_mtim.tv_nsec,missing[i] ? 0LL : (long long)st[i].st_ctim.tv_sec,missing[i] ? 0L : st[i].st_ctim.tv_nsec);
  if(n<0 || (size_t)n>=sizeof(signature)-used){ucv_put(result);result=NULL;goto done;}used+=(size_t)n;
 }
 ucv_object_add(result,"stamp",ucv_string_new(signature));
 char *binding=ucv_to_jsonstring(vm,result);
 bool ok=binding && hash_parts(tag,binding,boot,"mesh-manager/onboard/scope/v1");
 if(binding){memset(binding,0,strlen(binding));free(binding);}
 if(!ok){ucv_put(result);result=NULL;goto done;}
 ucv_object_add(result,"tag",ucv_string_new(tag));
 done:for(unsigned i=0;i<5;i++)if(raw[i]){memset(raw[i],0,strlen(raw[i]));free(raw[i]);}
 if(dir>=0)close(dir);
 return result ? result : failure(vm,"runtime_unavailable");
}
/* Explicit handoff gates read this bounded journal, never the UCI tree. A
 * known absent file is distinct from an unsafe or uncertain storage object. */
static uc_value_t *journal_read(uc_vm_t *vm,size_t nargs) {
 if(nargs)return failure(vm,"runtime_unavailable");
 int dir=open(MESH_ONBOARD_DURABLE,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 struct stat parent,path,st;char *raw=NULL;uc_value_t *result=NULL;
 if(dir<0 || fstat(dir,&parent) || !safe_stat(&parent,true))goto done;
 raw=read_file(dir,"state.json",JOURNAL_LIMIT,&st);
 bool absent=!raw && fstatat(dir,"state.json",&path,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT;
 if((!raw && !absent) || !path_same(dir,"state.json",&st,absent) ||
  lstat(MESH_ONBOARD_DURABLE,&path) || parent.st_dev!=path.st_dev || parent.st_ino!=path.st_ino)goto done;
 result=ucv_object_new(vm);ucv_object_add(result,"raw",raw ? ucv_string_new(raw) : NULL);
 done:if(raw){memset(raw,0,strlen(raw));free(raw);}if(dir>=0)close(dir);
 return result ? result : failure(vm,"runtime_unavailable");
}
static bool scope_matches(uc_vm_t *vm,uc_value_t *expected) {
 uc_value_t *actual=scope_read(vm,0);bool ok=false;
 const char *fields[]={"identity","key","boot","tag","join_ca","network_ca","cert","stamp"};
 if(ucv_type(expected)==UC_OBJECT && !ucv_object_get(actual,"error",NULL)) {
  ok=true;for(unsigned i=0;i<8;i++){const char *a=text_field(actual,fields[i],RAW_LIMIT),*b=text_field(expected,fields[i],RAW_LIMIT);
   if(((i<4 || i==7) && (!a || !b)) || (!a && ucv_type(ucv_object_get(actual,fields[i],NULL))!=UC_NULL) || (!b && ucv_type(ucv_object_get(expected,fields[i],NULL))!=UC_NULL) || (!a)!=(!b) || (a && strcmp(a,b))){ok=false;break;}}
 }
 bool has_state=false;ucv_object_get(expected,"state",&has_state);
 if(ok && has_state) {
  uc_value_t *journal=journal_read(vm,0),*want=ucv_object_get(expected,"state",NULL),*have=ucv_object_get(journal,"raw",NULL);
  ok=!ucv_object_get(journal,"error",NULL) && ucv_type(want)==ucv_type(have) &&
   (ucv_type(want)==UC_NULL || (ucv_type(want)==UC_STRING && ucv_string_length(want)==ucv_string_length(have) &&
    !memcmp(ucv_string_get(want),ucv_string_get(have),ucv_string_length(want))));
  ucv_put(journal);
 }
 ucv_put(actual);return ok;
}
static bool scope_tag_matches(uc_vm_t *vm,const char *tag,const char *boot) {
 uc_value_t *s=scope_read(vm,0);const char *a=text_field(s,"tag",64),*b=text_field(s,"boot",36);
 bool ok=a && b && !strcmp(a,tag) && !strcmp(b,boot);ucv_put(s);return ok;
}

/* Bounded native netlink requests. Created link ownership is the ACKed kernel
 * ifindex plus a session-specific MAC, never a guessed current name. */
struct packet {struct nlmsghdr n;unsigned char payload[4096];};
static bool attribute(struct packet *p,unsigned short kind,const void *data,size_t size) {
 size_t used=NLMSG_ALIGN(p->n.nlmsg_len),length=RTA_LENGTH(size);
 if(used+RTA_ALIGN(length)>sizeof(*p))return false;
 struct rtattr *a=(void *)((char *)p+used);a->rta_type=kind;a->rta_len=length;
 if(size)memcpy(RTA_DATA(a),data,size);
 memset((char *)a+length,0,RTA_ALIGN(length)-length);
 p->n.nlmsg_len=used+RTA_ALIGN(length);return true;
}
static int netlink_open(int protocol) {
 int fd=socket(AF_NETLINK,SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC,protocol);
 struct sockaddr_nl local={.nl_family=AF_NETLINK};
 if(fd>=0 && bind(fd,(struct sockaddr *)&local,sizeof(local))){close(fd);fd=-1;}return fd;
}
static int netlink_request(int fd,struct packet *p,uint64_t deadline,int *created) {
 struct sockaddr_nl kernel={.nl_family=AF_NETLINK};unsigned char data[8192];unsigned packets=0;
 p->n.nlmsg_seq=1;p->n.nlmsg_flags|=NLM_F_REQUEST|NLM_F_ACK;
 if(clock_ms()>=deadline)return -1;
 if(sendto(fd,p,p->n.nlmsg_len,0,(struct sockaddr *)&kernel,sizeof(kernel))!=(ssize_t)p->n.nlmsg_len)return -1;
 bool ack=false;
 while(clock_ms()<deadline && packets++<32) {
  struct pollfd pollfd={.fd=fd,.events=POLLIN};int remaining=(int)(deadline-clock_ms());
  if(remaining<=0 || poll(&pollfd,1,remaining)<=0 || clock_ms()>=deadline)return -1;
  struct sockaddr_nl source={0};socklen_t size=sizeof(source);
  ssize_t n=recvfrom(fd,data,sizeof(data),MSG_DONTWAIT,(struct sockaddr *)&source,&size);
  if(n<0 && (errno==EINTR || errno==EAGAIN))continue;
  if(n<=0 || n==(ssize_t)sizeof(data) || source.nl_pid!=0 || size!=sizeof(source))return -1;
  for(struct nlmsghdr *h=(void *)data;NLMSG_OK(h,n);h=NLMSG_NEXT(h,n)) {
   if(h->nlmsg_seq!=1)return -1;
   if(h->nlmsg_type==NLMSG_ERROR){if(h->nlmsg_len<NLMSG_LENGTH(sizeof(struct nlmsgerr)))return -1;
    int code=((struct nlmsgerr *)NLMSG_DATA(h))->error;if(code)return code;ack=true;}
   else if(created && h->nlmsg_type>=NLMSG_MIN_TYPE && h->nlmsg_len>=NLMSG_LENGTH(GENL_HDRLEN)) {
    int bytes=(int)h->nlmsg_len-NLMSG_HDRLEN-GENL_HDRLEN;
    for(struct rtattr *a=(void *)((char *)NLMSG_DATA(h)+GENL_HDRLEN);RTA_OK(a,bytes);a=RTA_NEXT(a,bytes))
     if((a->rta_type&NLA_TYPE_MASK)==NL80211_ATTR_IFINDEX && RTA_PAYLOAD(a)==4)memcpy(created,RTA_DATA(a),4);
    if(bytes)return -1;
   }
  }
  if(n)return -1;
  if(ack)return clock_ms()>=deadline || (created && *created<=0) ? -1 : 0;
 }
 return -1;
}
static int family_id(int fd,uint64_t deadline) {
 struct packet p={.n={.nlmsg_len=NLMSG_LENGTH(GENL_HDRLEN),.nlmsg_type=GENL_ID_CTRL,.nlmsg_flags=NLM_F_REQUEST,.nlmsg_seq=2}};
 struct genlmsghdr *g=NLMSG_DATA(&p.n);g->cmd=CTRL_CMD_GETFAMILY;g->version=1;
 const char family[]="nl80211";if(!attribute(&p,CTRL_ATTR_FAMILY_NAME,family,sizeof(family)))return -1;
 struct sockaddr_nl kernel={.nl_family=AF_NETLINK};unsigned char data[8192];
 if(clock_ms()>=deadline)return -1;
 if(sendto(fd,&p,p.n.nlmsg_len,0,(void *)&kernel,sizeof(kernel))!=(ssize_t)p.n.nlmsg_len)return -1;
 struct pollfd pollfd={.fd=fd,.events=POLLIN};uint64_t now=clock_ms();if(now>=deadline || poll(&pollfd,1,(int)(deadline-now))<=0 || clock_ms()>=deadline)return -1;
 struct sockaddr_nl source={0};socklen_t size=sizeof(source);ssize_t n=recvfrom(fd,data,sizeof(data),0,(void *)&source,&size);
 if(n<=0 || n==(ssize_t)sizeof(data) || source.nl_pid || size!=sizeof(source))return -1;
 struct nlmsghdr *h=(void *)data;if(!NLMSG_OK(h,n) || h->nlmsg_seq!=2 || h->nlmsg_type!=GENL_ID_CTRL || h->nlmsg_len<NLMSG_LENGTH(GENL_HDRLEN))return -1;
 int remaining=h->nlmsg_len-NLMSG_HDRLEN-GENL_HDRLEN;
 for(struct rtattr *a=(void *)((char *)NLMSG_DATA(h)+GENL_HDRLEN);RTA_OK(a,remaining);a=RTA_NEXT(a,remaining))
  if(a->rta_type==CTRL_ATTR_FAMILY_ID && RTA_PAYLOAD(a)==2){uint16_t id;memcpy(&id,RTA_DATA(a),2);return id;}
 return -1;
}
static bool create_link(struct actor *a) {
 int fd=netlink_open(NETLINK_GENERIC),family=fd<0 ? -1 : family_id(fd,budget(a,1500));bool ok=false;
 if(family<0)goto done;
 struct packet p={.n={.nlmsg_len=NLMSG_LENGTH(GENL_HDRLEN),.nlmsg_type=(unsigned short)family,.nlmsg_flags=NLM_F_CREATE|NLM_F_EXCL}};
 struct genlmsghdr *g=NLMSG_DATA(&p.n);g->cmd=NL80211_CMD_NEW_INTERFACE;g->version=1;
 uint32_t phy=a->phy,kind=NL80211_IFTYPE_STATION;
 if(!attribute(&p,NL80211_ATTR_WIPHY,&phy,4) || !attribute(&p,NL80211_ATTR_IFNAME,IFACE,sizeof(IFACE)) ||
  !attribute(&p,NL80211_ATTR_IFTYPE,&kind,4) || !attribute(&p,NL80211_ATTR_MAC,a->mac,6))goto done;
 if(clock_ms()>=a->setup_deadline)goto done;
 a->link_requested=true;ok=netlink_request(fd,&p,budget(a,3000),&a->ifindex)==0 && clock_ms()<a->setup_deadline;
 done:if(fd>=0)close(fd);return ok;
}
static bool link_current(struct actor *a) {
 char buf[128],path[128],expected[32];
 snprintf(path,sizeof(path),"/sys/class/net/" IFACE "/ifindex");int fd=open(path,O_RDONLY|O_CLOEXEC);
 ssize_t n=fd<0 ? -1 : read(fd,buf,sizeof(buf)-1);if(fd>=0)close(fd);
 if(n<=0)return false;
 buf[n]=0;
 char *end;long index=strtol(buf,&end,10);if(index!=a->ifindex || *end!='\n' || end[1])return false;
 fd=open("/sys/class/net/" IFACE "/address",O_RDONLY|O_CLOEXEC);n=fd<0 ? -1 : read(fd,buf,sizeof(buf)-1);
 if(fd>=0)close(fd);
 if(n!=18)return false;
 buf[n]=0;
 snprintf(expected,sizeof(expected),"%02x:%02x:%02x:%02x:%02x:%02x\n",a->mac[0],a->mac[1],a->mac[2],a->mac[3],a->mac[4],a->mac[5]);
 if(strcmp(buf,expected))return false;
 n=readlink("/sys/class/net/" IFACE "/phy80211",buf,sizeof(buf)-1);if(n<=0 || n==(ssize_t)sizeof(buf)-1)return false;buf[n]=0;
 char *base=strrchr(buf,'/');snprintf(expected,sizeof(expected),"phy%d",a->phy);
 return !strcmp(base ? base+1 : buf,expected);
}
static bool link_operation(struct actor *a,bool remove) {
 if(!link_current(a))return false;
 if(remove) {
  // cfg80211-created wireless links have no rtnl_link_ops->dellink. Delete
  // through the same nl80211 API, using only this exact session ifindex.
  int fd=netlink_open(NETLINK_GENERIC),family=fd<0 ? -1 : family_id(fd,budget(a,1500));bool ok=false;
  if(family>=0 && link_current(a)) {
   struct packet p={.n={.nlmsg_len=NLMSG_LENGTH(GENL_HDRLEN),.nlmsg_type=(unsigned short)family}};
   struct genlmsghdr *g=NLMSG_DATA(&p.n);g->cmd=NL80211_CMD_DEL_INTERFACE;g->version=1;
   ok=attribute(&p,NL80211_ATTR_IFINDEX,&a->ifindex,4) && netlink_request(fd,&p,budget(a,1500),NULL)==0;
  }
  if(fd>=0)close(fd);
  return ok;
 }
 int fd=netlink_open(NETLINK_ROUTE);if(fd<0)return false;
 struct packet p={.n={.nlmsg_len=NLMSG_LENGTH(sizeof(struct ifinfomsg)),.nlmsg_type=remove ? RTM_DELLINK : RTM_NEWLINK}};
 struct ifinfomsg *m=NLMSG_DATA(&p.n);m->ifi_family=AF_UNSPEC;m->ifi_index=a->ifindex;
 if(!remove){m->ifi_flags=IFF_UP;m->ifi_change=IFF_UP;}
 bool ok=netlink_request(fd,&p,budget(a,1500),NULL)==0;close(fd);return ok;
}
static char *inventory_read(struct actor *a);
static bool prepare_link(struct actor *a) {
 // Disable automatic IPv6 address generation on this new, unbridged IPv4
 // bootstrap interface only. Other LAN/WAN/radio devices are never touched.
 if(!link_current(a))return false;
 int parent=open("/proc/sys/net/ipv6/conf",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if(parent<0) {
  // IPv4-only kernels have neither IPv6 configuration nor the kernel IPv6
  // address table. A partial/inaccessible tree is not this supported case.
  int error=errno;struct stat table;
  if(error!=ENOENT || lstat("/proc/net/if_inet6",&table)==0 || errno!=ENOENT)return false;
  char *actual=inventory_read(a);bool ok=actual && a->inventory && !strcmp(actual,a->inventory);
  for(char *line=actual;ok && line && *line;){if(!strncmp(line+1,"410a",4) || !strncmp(line+1,"520a",4))ok=false;
   char *next=strchr(line,'\n');line=next ? next+1 : NULL;}
  free(actual);return ok && link_current(a) && clock_ms()<a->setup_deadline;
 }
 int fd=netlink_open(NETLINK_ROUTE);if(fd<0){close(parent);return false;}
 struct packet p={.n={.nlmsg_len=NLMSG_LENGTH(sizeof(struct ifinfomsg)),.nlmsg_type=RTM_NEWLINK}};
 struct ifinfomsg *m=NLMSG_DATA(&p.n);m->ifi_family=AF_UNSPEC;m->ifi_index=a->ifindex;
 size_t outer=NLMSG_ALIGN(p.n.nlmsg_len);
 bool ok=attribute(&p,IFLA_AF_SPEC|NLA_F_NESTED,NULL,0);
 size_t inet6=NLMSG_ALIGN(p.n.nlmsg_len);ok=ok && attribute(&p,AF_INET6|NLA_F_NESTED,NULL,0);
 uint8_t mode=IN6_ADDR_GEN_MODE_NONE;ok=ok && attribute(&p,IFLA_INET6_ADDR_GEN_MODE,&mode,1);
 if(ok){((struct rtattr *)((char *)&p+outer))->rta_len=p.n.nlmsg_len-outer;
  ((struct rtattr *)((char *)&p+inet6))->rta_len=p.n.nlmsg_len-inet6;
  ok=netlink_request(fd,&p,budget(a,1500),NULL)==0 && link_current(a);}
 close(fd);
 // addr_gen_mode=NONE suppresses link-local addresses, but carrier-up may
 // still create a kernel ff00::/8 route. IFLA_INET6_CONF is read-only in
 // Linux's set_link_af; disable IPv6 on this newly owned bootstrap link only.
 if(!ok || !link_current(a) || clock_ms()>=a->setup_deadline){close(parent);return false;}
 int dir=parent<0 ? -1 : openat(parent,IFACE,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 struct stat directory,st;char value[4]={0};
 ok=dir>=0 && !fstat(dir,&directory) && S_ISDIR(directory.st_mode) && directory.st_uid==MESH_ONBOARD_UID &&
  path_same(parent,IFACE,&directory,false) && link_current(a);
 fd=ok ? openat(dir,"disable_ipv6",O_RDWR|O_NOFOLLOW|O_CLOEXEC) : -1;
 ok=fd>=0 && !fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_uid==MESH_ONBOARD_UID &&
  path_same(dir,"disable_ipv6",&st,false) && path_same(parent,IFACE,&directory,false) &&
  link_current(a) && clock_ms()<a->setup_deadline && write_all(fd,"1\n",2,budget(a,500)) &&
  lseek(fd,0,SEEK_SET)==0 && read(fd,value,sizeof(value))==2 && !memcmp(value,"1\n",2) &&
  path_same(parent,IFACE,&directory,false) && link_current(a) && clock_ms()<a->setup_deadline;
 if(fd>=0 && close(fd))ok=false;
 if(dir>=0)close(dir);
 if(parent>=0)close(parent);
 return ok;
}
static bool address_operation(struct actor *a,bool add) {
 if(!link_current(a))return false;
 int fd=netlink_open(NETLINK_ROUTE);if(fd<0)return false;
 struct packet p={.n={.nlmsg_len=NLMSG_LENGTH(sizeof(struct ifaddrmsg)),.nlmsg_type=add ? RTM_NEWADDR : RTM_DELADDR,
  .nlmsg_flags=add ? NLM_F_CREATE|NLM_F_EXCL : 0}};
 struct ifaddrmsg *m=NLMSG_DATA(&p.n);m->ifa_family=AF_INET;m->ifa_prefixlen=32;m->ifa_scope=RT_SCOPE_UNIVERSE;m->ifa_index=a->ifindex;
 bool ok=attribute(&p,IFA_LOCAL,&a->lease,4) && attribute(&p,IFA_ADDRESS,&a->lease,4) && netlink_request(fd,&p,budget(a,1500),NULL)==0;
 close(fd);return ok;
}
static bool route_operation(struct actor *a,bool add) {
 if(!link_current(a))return false;
 int fd=netlink_open(NETLINK_ROUTE);if(fd<0)return false;
 struct packet p={.n={.nlmsg_len=NLMSG_LENGTH(sizeof(struct rtmsg)),.nlmsg_type=add ? RTM_NEWROUTE : RTM_DELROUTE,
  .nlmsg_flags=add ? NLM_F_CREATE|NLM_F_EXCL : 0}};
 struct rtmsg *m=NLMSG_DATA(&p.n);m->rtm_family=AF_INET;m->rtm_dst_len=32;m->rtm_table=RT_TABLE_MAIN;
 m->rtm_protocol=RTPROT_STATIC;m->rtm_scope=RT_SCOPE_LINK;m->rtm_type=RTN_UNICAST;
 bool ok=attribute(&p,RTA_DST,&a->controller,4) && attribute(&p,RTA_OIF,&a->ifindex,4) &&
  attribute(&p,RTA_PREFSRC,&a->lease,4) && netlink_request(fd,&p,budget(a,1500),NULL)==0;
 close(fd);return ok;
}
static bool ipv4(const char *text,struct in_addr *out,bool private) {
 if(!text || inet_pton(AF_INET,text,out)!=1)return false;
 char canonical[INET_ADDRSTRLEN];
 if(!inet_ntop(AF_INET,out,canonical,sizeof(canonical)) || strcmp(text,canonical))return false;
 uint32_t ip=ntohl(out->s_addr);if((ip>>24)==0 || (ip>>24)==127 || (ip>>28)>=14 || ip==UINT32_MAX)return false;
 return !private || (ip>>24)==10 || (ip>>20)==0xac1 || (ip>>16)==0xc0a8;
}
/* The link starts empty and unbridged. This inventory records all attached
 * address/route semantics; only verified additions from our DHCP operation
 * may extend it. Timer stamps and IPv6 DAD's tentative flag are volatile. */
struct inventory_items {char *item[32];size_t count,total;unsigned owned_address,owned_local,owned_root;};
static int item_compare(const void *x,const void *y){return strcmp(*(char *const *)x,*(char *const *)y);}
static bool dump_item(struct actor *a,struct inventory_items *items,struct nlmsghdr *h,bool address) {
 size_t header=address ? sizeof(struct ifaddrmsg) : sizeof(struct rtmsg);
 if(h->nlmsg_len<NLMSG_LENGTH(header))return false;
 struct rtattr *attrs[256]={0};int bytes=(int)h->nlmsg_len-NLMSG_HDRLEN-NLMSG_ALIGN(header);
 if(bytes<0)return false;
 for(struct rtattr *r=(void *)((char *)NLMSG_DATA(h)+NLMSG_ALIGN(header));RTA_OK(r,bytes);r=RTA_NEXT(r,bytes)) {
  unsigned kind=r->rta_type&NLA_TYPE_MASK;if(!kind || kind>=256 || attrs[kind])return false;attrs[kind]=r;
 }
 if(bytes)return false;
 bool relevant=false,own=false;unsigned char clean[32]={0};
 memcpy(clean,NLMSG_DATA(h),header);
 if(address) {
  struct ifaddrmsg *m=(void *)clean;relevant=m->ifa_index==(unsigned)a->ifindex;
  if(m->ifa_family==AF_INET && attrs[IFA_LOCAL] && RTA_PAYLOAD(attrs[IFA_LOCAL])==4 &&
   !memcmp(RTA_DATA(attrs[IFA_LOCAL]),&a->controller,4)){a->address_conflict=true;return false;} // Local table shadows a host route.
  m->ifa_flags&=~IFA_F_TENTATIVE;
  own=a->addr_created && relevant && m->ifa_flags==IFA_F_PERMANENT && m->ifa_family==AF_INET && m->ifa_prefixlen==32 && m->ifa_scope==RT_SCOPE_UNIVERSE &&
   attrs[IFA_LOCAL] && RTA_PAYLOAD(attrs[IFA_LOCAL])==4 && !memcmp(RTA_DATA(attrs[IFA_LOCAL]),&a->lease,4) &&
   (!attrs[IFA_ADDRESS] || (RTA_PAYLOAD(attrs[IFA_ADDRESS])==4 && !memcmp(RTA_DATA(attrs[IFA_ADDRESS]),&a->lease,4)));
 }else {
  struct rtmsg *m=(void *)clean;int oif=0,iif=0;
  // Carrier loss changes this kernel observation, including when we stop
  // our own supplicant during cleanup. Route policy and all other flags
  // remain part of the exact inventory.
  m->rtm_flags&=~RTNH_F_LINKDOWN;
  if(attrs[RTA_OIF]){if(RTA_PAYLOAD(attrs[RTA_OIF])!=4)return false;memcpy(&oif,RTA_DATA(attrs[RTA_OIF]),4);}
  if(attrs[RTA_IIF]){if(RTA_PAYLOAD(attrs[RTA_IIF])!=4)return false;memcpy(&iif,RTA_DATA(attrs[RTA_IIF]),4);}
  if(attrs[RTA_NH_ID])return false; // This slice does not resolve nexthop groups.
  if(attrs[RTA_MULTIPATH]) {
   int remaining=RTA_PAYLOAD(attrs[RTA_MULTIPATH]);
   for(struct rtnexthop *n=RTA_DATA(attrs[RTA_MULTIPATH]);RTNH_OK(n,remaining);n=RTNH_NEXT(n)) {
    if(n->rtnh_ifindex==a->ifindex)relevant=true;
    remaining-=RTNH_ALIGN(n->rtnh_len);
   }
   if(remaining)return false;
  }
  relevant=relevant || oif==a->ifindex || iif==a->ifindex;
  bool dst=attrs[RTA_DST] && RTA_PAYLOAD(attrs[RTA_DST])==4;
  own=a->addr_created && relevant && m->rtm_flags==0 && !iif && !attrs[RTA_MULTIPATH] && !attrs[RTA_GATEWAY] && !attrs[RTA_VIA] &&
   m->rtm_family==AF_INET && m->rtm_dst_len==32 && m->rtm_src_len==0 && m->rtm_tos==0 && dst &&
   attrs[RTA_PREFSRC] && RTA_PAYLOAD(attrs[RTA_PREFSRC])==4 && !memcmp(RTA_DATA(attrs[RTA_PREFSRC]),&a->lease,4) &&
   ((a->route_created && m->rtm_table==RT_TABLE_MAIN && m->rtm_protocol==RTPROT_STATIC && m->rtm_scope==RT_SCOPE_LINK &&
      m->rtm_type==RTN_UNICAST && !memcmp(RTA_DATA(attrs[RTA_DST]),&a->controller,4)) ||
    (m->rtm_table==RT_TABLE_LOCAL && m->rtm_protocol==RTPROT_KERNEL && m->rtm_scope==RT_SCOPE_HOST &&
      m->rtm_type==RTN_LOCAL && !memcmp(RTA_DATA(attrs[RTA_DST]),&a->lease,4)));
 }
 if(!relevant)return true;
 if(own)for(unsigned k=1;k<256;k++)if(attrs[k]) {
  if(address) {
   if(k!=IFA_LOCAL && k!=IFA_ADDRESS && k!=IFA_LABEL && k!=IFA_CACHEINFO && k!=IFA_FLAGS)own=false;
   if(k==IFA_LABEL && (RTA_PAYLOAD(attrs[k])!=sizeof(IFACE) || memcmp(RTA_DATA(attrs[k]),IFACE,sizeof(IFACE))))own=false;
   if(k==IFA_FLAGS && (RTA_PAYLOAD(attrs[k])!=4 || *(uint32_t *)RTA_DATA(attrs[k])!=IFA_F_PERMANENT))own=false;
   if(k==IFA_CACHEINFO && (RTA_PAYLOAD(attrs[k])!=sizeof(struct ifa_cacheinfo) ||
    ((struct ifa_cacheinfo *)RTA_DATA(attrs[k]))->ifa_prefered!=UINT32_MAX ||
    ((struct ifa_cacheinfo *)RTA_DATA(attrs[k]))->ifa_valid!=UINT32_MAX))own=false;
  }else {
   if(k!=RTA_OIF && k!=RTA_DST && k!=RTA_PREFSRC && k!=RTA_TABLE)own=false;
   if(k==RTA_TABLE && (RTA_PAYLOAD(attrs[k])!=4 || *(uint32_t *)RTA_DATA(attrs[k])!=((struct rtmsg *)clean)->rtm_table))own=false;
  }
 }
 if(items->count>=32)return false;
 unsigned char encoded[2048];size_t used=0;encoded[used++]=address ? 'A' : 'R';memcpy(encoded+used,clean,header);used+=header;
 for(unsigned k=1;k<256;k++)if(attrs[k]) {
  struct rtattr *r=attrs[k];size_t len=RTA_PAYLOAD(r);if(used+len+4>sizeof(encoded))return false;
  encoded[used++]=k>>8;encoded[used++]=k;encoded[used++]=len>>8;encoded[used++]=len;
  memcpy(encoded+used,RTA_DATA(r),len);
  if(address && k==IFA_CACHEINFO) {
   if(len!=sizeof(struct ifa_cacheinfo))return false;
   struct ifa_cacheinfo info;memcpy(&info,encoded+used,len);info.cstamp=0;info.tstamp=0;memcpy(encoded+used,&info,len);
  }
  if(address && k==IFA_FLAGS) {
   if(len!=4)return false;
   uint32_t flags;memcpy(&flags,encoded+used,4);flags&=~IFA_F_TENTATIVE;memcpy(encoded+used,&flags,4);
  }
  used+=len;
 }
 if(items->total+used*2+3>16384)return false;
 char *text=malloc(used*2+3);if(!text)return false;text[0]=own ? '+' : '-';
 if(own){if(address)items->owned_address++;else if(((struct rtmsg *)clean)->rtm_table==RT_TABLE_LOCAL)items->owned_local++;else items->owned_root++;}
 for(size_t i=0;i<used;i++)snprintf(text+1+i*2,3,"%02x",encoded[i]);
 items->item[items->count++]=text;items->total+=used*2+2;return true;
}
static bool inventory_dump(struct actor *a,struct inventory_items *items,bool address,uint64_t deadline) {
 int fd=netlink_open(NETLINK_ROUTE);if(fd<0)return false;
 struct packet p={.n={.nlmsg_len=NLMSG_LENGTH(address ? sizeof(struct ifaddrmsg) : sizeof(struct rtmsg)),
  .nlmsg_type=address ? RTM_GETADDR : RTM_GETROUTE,.nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP,.nlmsg_seq=3}};
 ((struct rtgenmsg *)NLMSG_DATA(&p.n))->rtgen_family=AF_UNSPEC;
 struct sockaddr_nl kernel={.nl_family=AF_NETLINK};bool ok=false;size_t count=0,total=0;
 if(clock_ms()>=deadline)goto done;
 if(sendto(fd,&p,p.n.nlmsg_len,0,(void *)&kernel,sizeof(kernel))!=(ssize_t)p.n.nlmsg_len)goto done;
 while(clock_ms()<deadline && count++<64) {
  struct pollfd pollfd={.fd=fd,.events=POLLIN};uint64_t now=clock_ms();if(now>=deadline || poll(&pollfd,1,(int)(deadline-now))<=0 || clock_ms()>=deadline)goto done;
  unsigned char data[16384];struct sockaddr_nl source={0};socklen_t size=sizeof(source);
  ssize_t n=recvfrom(fd,data,sizeof(data),MSG_DONTWAIT,(void *)&source,&size);
  if(n<0 && (errno==EINTR || errno==EAGAIN))continue;
  if(n<=0 || n==(ssize_t)sizeof(data) || source.nl_pid || size!=sizeof(source) || (total+=(size_t)n)>65536)goto done;
  for(struct nlmsghdr *h=(void *)data;NLMSG_OK(h,n);h=NLMSG_NEXT(h,n)) {
   if(h->nlmsg_seq!=3 || h->nlmsg_flags&NLM_F_DUMP_INTR)goto done;
   if(h->nlmsg_type==NLMSG_DONE){ok=h->nlmsg_len==NLMSG_LENGTH(0) ||
     (h->nlmsg_len==NLMSG_LENGTH(sizeof(int)) && *(int *)NLMSG_DATA(h)==0);goto done;}
   if(h->nlmsg_type!=(address ? RTM_NEWADDR : RTM_NEWROUTE) || !dump_item(a,items,h,address))goto done;
  }
  if(n)goto done;
 }
 done:close(fd);return ok;
}
static char *inventory_read(struct actor *a) {
 if(!link_current(a))return NULL;
 struct stat master;if(!lstat("/sys/class/net/" IFACE "/master",&master) || errno!=ENOENT)return NULL;
 struct inventory_items items={0};char *result=NULL;uint64_t deadline=budget(a,1500);
 if(inventory_dump(a,&items,true,deadline) && inventory_dump(a,&items,false,deadline) && link_current(a) &&
  (!a->addr_created || (items.owned_address==1 && items.owned_local==1)) &&
  (!a->route_created || (a->addr_created && items.owned_root==1))) {
  qsort(items.item,items.count,sizeof(items.item[0]),item_compare);result=malloc(items.total+1);
  if(result){size_t used=0;for(size_t i=0;i<items.count;i++){size_t len=strlen(items.item[i]);memcpy(result+used,items.item[i],len);used+=len;result[used++]='\n';}result[used]=0;}
 }
 for(size_t i=0;i<items.count;i++)free(items.item[i]);
 return result;
}
static bool inventory_same(struct actor *a) {
 char *actual=inventory_read(a);bool ok=actual && a->inventory && !strcmp(actual,a->inventory);free(actual);return ok;
}
static bool inventory_extend(struct actor *a) {
 char *actual=inventory_read(a);if(!actual || !a->inventory){free(actual);return false;}
 char *before=strdup(a->inventory),*after=strdup(actual);bool ok=before && after;
 char *save=NULL;
 for(char *line=ok ? strtok_r(before,"\n",&save) : NULL;line;line=strtok_r(NULL,"\n",&save)) {
  size_t len=strlen(line);bool found=false;
  for(char *at=actual;*at;){char *end=strchr(at,'\n');if(!end)break;if((size_t)(end-at)==len && !memcmp(at,line,len)){found=true;break;}at=end+1;}
  if(!found){ok=false;break;}
 }
 save=NULL;
 for(char *line=ok ? strtok_r(after,"\n",&save) : NULL;line;line=strtok_r(NULL,"\n",&save)) {
  if(line[0]=='+')continue;
  size_t len=strlen(line);bool found=false;
  for(char *at=a->inventory;*at;){char *end=strchr(at,'\n');if(!end)break;if((size_t)(end-at)==len && !memcmp(at,line,len)){found=true;break;}at=end+1;}
  if(!found){ok=false;break;}
 }
 free(before);free(after);if(ok){free(a->inventory);a->inventory=actual;}else free(actual);return ok;
}

static bool unchanged(struct actor *a) {
 if(a->lost || !directory_same(a->dir))return false;
 if(a->state_exists){char *raw=read_file(a->dir,STATE,LIMIT,NULL);bool ok=raw && a->last_raw && !strcmp(raw,a->last_raw) && path_same(a->dir,STATE,&a->state_stat,false);free(raw);if(!ok)return false;}
 else if(!path_same(a->dir,STATE,NULL,true))return false;
 if(a->config_exists && !path_same(a->dir,CONFIG,&a->config_stat,false))return false;
 if(a->socket_exists && !path_same(a->dir,CONTROL,&a->socket_stat,false))return false;
 return directory_same(a->dir) && path_same(a->dir,STATE,&a->state_stat,!a->state_exists) &&
  (!a->config_exists || path_same(a->dir,CONFIG,&a->config_stat,false)) &&
  (!a->socket_exists || path_same(a->dir,CONTROL,&a->socket_stat,false));
}
static bool publish(struct actor *a,const char *raw) {
 if(!raw || !strlen(raw) || strlen(raw)>LIMIT)return false;
 if(!unchanged(a)){a->lost=true;return false;}
 int fd=openat(a->dir,STAGE,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);struct stat initial={0},staging={0};
 if(fd<0)return false;
 bool created=!fstat(fd,&initial) && safe_stat(&initial,false);
 bool written=created && write_all(fd,raw,strlen(raw),budget(a,500));
 // Always capture the new inode even after ENOSPC/short write. Failure to
 // write is not loss of owner; safely discard only our unpublished inode.
 bool owned=created && !fstat(fd,&staging) && safe_stat(&staging,false) &&
  initial.st_dev==staging.st_dev && initial.st_ino==staging.st_ino;
 bool ok=written && owned;
 if(close(fd))ok=false;
 if(ok){char *actual=read_file(a->dir,STAGE,LIMIT,NULL);ok=actual && !strcmp(actual,raw) && path_same(a->dir,STAGE,&staging,false);free(actual);}
 if(!unchanged(a)){a->lost=true;ok=false;}
 if(ok)ok=renameat(a->dir,STAGE,a->dir,STATE)==0;
 if(ok){free(a->last_raw);a->last_raw=strdup(raw);a->state_exists=true;struct stat actual;char *check=read_file(a->dir,STATE,LIMIT,&actual);
  ok=a->last_raw && check && !strcmp(check,raw) && actual.st_dev==staging.st_dev && actual.st_ino==staging.st_ino &&
  actual.st_size==staging.st_size && directory_same(a->dir);free(check);if(ok)a->state_stat=actual;else a->lost=true;}
 if(!ok && owned && path_same(a->dir,STAGE,&staging,false))unlinkat(a->dir,STAGE,0);
 return ok;
}
static void reap(pid_t pid,bool *done,bool stop) {
 if(pid<=0 || *done)return;
 pid_t found=waitpid(pid,NULL,WNOHANG);
 // A positive waitpid=0 proves an exact unreaped child, so PID reuse cannot
 // redirect this signal. Reaping remains bounded even for a kernel D-state.
 if(found==0 && stop) {
  kill(pid,SIGKILL);uint64_t deadline=clock_ms()+1000;struct timespec pause={0,10000000};
  do{found=waitpid(pid,NULL,WNOHANG);if(found==0)nanosleep(&pause,NULL);}while((found==0 || (found<0 && errno==EINTR)) && clock_ms()<deadline);
 }
 if(found==pid || (found<0 && errno==ECHILD))*done=true;
}
static int close_inherited(int keep1,int keep2) {
#ifdef SYS_close_range
 // Dedicated children retain only stdio and the normalized lease capability.
 if(keep1==LEASE_FD && keep2<0 &&
  syscall(SYS_close_range,3U,(unsigned)LEASE_FD-1,0U)==0 &&
  syscall(SYS_close_range,(unsigned)LEASE_FD+1,UINT_MAX,0U)==0)return 0;
 if(keep1<=3 && keep2<=3 && syscall(SYS_close_range,4U,UINT_MAX,0U)==0)return 0;
#endif
 long maximum=sysconf(_SC_OPEN_MAX);if(maximum<0 || maximum>4096)return -1;
 for(int fd=3;fd<maximum;fd++)if(fd!=keep1 && fd!=keep2)close(fd);
 return 0;
}
static pid_t spawn(char *const argv[],int lease_fd,int output_fd) {
 pid_t parent=getpid(),pid=fork();if(pid!=0)return pid;
 if(prctl(PR_SET_PDEATHSIG,SIGKILL) || getppid()!=parent)_exit(127);
 int null=open("/dev/null",O_RDWR);if(null<0 || dup2(null,0)<0 || dup2(output_fd>=0 ? output_fd : null,1)<0 || dup2(null,2)<0)_exit(127);
 if(lease_fd>=0 && dup2(lease_fd,LEASE_FD)<0)_exit(127);
 if(lease_fd>=0){int flags=fcntl(LEASE_FD,F_GETFD);if(flags<0 || fcntl(LEASE_FD,F_SETFD,flags&~FD_CLOEXEC))_exit(127);}
 else close(3);
 if(close_inherited(lease_fd>=0 ? LEASE_FD : -1,-1))_exit(127);
 // No inherited user environment, proxy variables or LD_PRELOAD. udhcpc adds
 // only its own documented DHCP fields when invoking the fixed lease hook.
 char *environment[]={"PATH=/usr/sbin:/usr/bin:/sbin:/bin",NULL};execve(argv[0],argv,environment);_exit(127);
}
static bool owned_socket(struct actor *a) {
 int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0);if(fd<0)return false;
 struct sockaddr_un address={.sun_family=AF_UNIX};
 if(snprintf(address.sun_path,sizeof(address.sun_path),MESH_ONBOARD_ROOT "/" DIRECTORY "/" CONTROL)>=(int)sizeof(address.sun_path)){close(fd);return false;}
 mode_t old=umask(0077);int result=bind(fd,(void *)&address,sizeof(address));umask(old);
 if(result || listen(fd,1) || fstatat(a->dir,CONTROL,&a->socket_stat,AT_SYMLINK_NOFOLLOW) ||
  !S_ISSOCK(a->socket_stat.st_mode) || a->socket_stat.st_uid!=MESH_ONBOARD_UID || a->socket_stat.st_mode&0077 || a->socket_stat.st_nlink!=1){close(fd);return false;}
 a->control=fd;a->socket_exists=true;return true;
}
static bool requested_stop(struct actor *a,int timeout) {
 if(a->pending>=0)return true;
 struct pollfd p={.fd=a->control,.events=POLLIN};if(poll(&p,1,timeout)<=0)return false;
 int client=accept4(a->control,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);if(client<0)return false;
 struct ucred peer;socklen_t size=sizeof(peer);char message[PERMIT_LIMIT+1]={0};
 bool stop=!getsockopt(client,SOL_SOCKET,SO_PEERCRED,&peer,&size) && size==sizeof(peer) && peer.uid==MESH_ONBOARD_UID;
 struct pollfd incoming={.fd=client,.events=POLLIN};
 if(!stop || poll(&incoming,1,100)<=0){close(client);return false;}
 ssize_t length=recv(client,message,PERMIT_LIMIT,MSG_DONTWAIT|MSG_TRUNC);
 if(length>32 && length<PERMIT_LIMIT && a->setup_complete && a->permit_fd<0 && unchanged(a)) {
  message[length]=0;json_object *command=parse_json(message),*generation=NULL;
  bool permitted=command && json_object_object_get_ex(command,"generation",&generation) && generation &&
   json_object_get_type(generation)==json_type_string && !strcmp(json_object_get_string(generation),a->generation);
  if(permitted){a->permit_raw=strdup(message);if(a->permit_raw){a->permit_fd=client;json_object_put(command);return false;}}
  json_object_put(command);
 }
 stop=length==32 && !memcmp(message,a->generation,32) && unchanged(a);
 if(!stop){close(client);return false;}a->pending=client;return true;
}
static struct actor *this_actor(uc_vm_t *vm) {return uc_fn_thisval("mesh_onboard.actor");}
static const char *json_text(json_object *object,const char *key,size_t maximum) {
 json_object *value=NULL;if(!object || !json_object_object_get_ex(object,key,&value) || !value || json_object_get_type(value)!=json_type_string)return NULL;
 const char *text=json_object_get_string(value);size_t length=(size_t)json_object_get_string_len(value);
 return length>0 && length<=maximum && !memchr(text,0,length) ? text : NULL;
}
static bool hex_text(const char *value,size_t length) {
 return value && strlen(value)==length && strspn(value,"0123456789abcdef")==length;
}
static bool ca_pin(const char *pem,const char *pin) {
 if(!pem || !hex_text(pin,64) || strlen(pem)>4096)return false;
 BIO *bio=BIO_new_mem_buf(pem,-1);X509 *cert=bio ? PEM_read_bio_X509(bio,NULL,NULL,NULL) : NULL;
 unsigned char digest[32];unsigned length=0;char fingerprint[65];
 bool ok=cert && X509_digest(cert,EVP_sha256(),digest,&length)==1 && length==32;
 if(ok){for(unsigned i=0;i<32;i++)snprintf(fingerprint+i*2,3,"%02x",digest[i]);ok=!strcmp(fingerprint,pin);}
 X509_free(cert);BIO_free(bio);return ok;
}
static bool device_key_matches(const char *pem,const char *node,const char *fingerprint) {
 if(!pem || !hex_text(node,32) || !hex_text(fingerprint,64) || strlen(pem)>RAW_LIMIT)return false;
 BIO *bio=BIO_new_mem_buf(pem,-1);EVP_PKEY *key=bio ? PEM_read_bio_PrivateKey(bio,NULL,NULL,NULL) : NULL;
 unsigned char *der=NULL,digest[32];unsigned size=0;int length=key ? i2d_PUBKEY(key,&der) : -1;
 const unsigned char ed25519_spki[]={0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00};
 char actual[65];bool ok=key && length==44 && !memcmp(der,ed25519_spki,sizeof(ed25519_spki)) &&
  EVP_Digest(der,(size_t)length,digest,&size,EVP_sha256(),NULL)==1 && size==32;
 if(ok){for(unsigned i=0;i<32;i++)snprintf(actual+i*2,3,"%02x",digest[i]);ok=!strcmp(actual,fingerprint) && !strncmp(actual,node,32);}
 OPENSSL_free(der);EVP_PKEY_free(key);BIO_free(bio);return ok;
}
static bool digest_raw(const char *raw,char result[65]) {
 unsigned char value[32];unsigned size=0;
 if(!raw || EVP_Digest(raw,strlen(raw),value,&size,EVP_sha256(),NULL)!=1 || size!=32)return false;
 for(unsigned i=0;i<32;i++)snprintf(result+2*i,3,"%02x",value[i]);
 return true;
}
static bool raw_digest_equals(const char *raw,const char *expected) {
 char actual[65];return hex_text(expected,64) && digest_raw(raw,actual) && !strcmp(actual,expected);
}
static bool serialized_digest_equals(uc_vm_t *vm,uc_value_t *value,const char *expected) {
 char *raw=ucv_to_jsonstring(vm,value);bool ok=raw && raw_digest_equals(raw,expected);free(raw);return ok;
}
static bool leaf_matches(const char *ca,const char *pem,const char *key_pem,const char *node) {
 BIO *a=BIO_new_mem_buf(ca,-1),*b=BIO_new_mem_buf(pem,-1),*k=BIO_new_mem_buf(key_pem,-1);
 X509 *issuer=a ? PEM_read_bio_X509(a,NULL,NULL,NULL) : NULL,*leaf=b ? PEM_read_bio_X509(b,NULL,NULL,NULL) : NULL;
 EVP_PKEY *key=k ? PEM_read_bio_PrivateKey(k,NULL,NULL,NULL) : NULL;
 X509_STORE *store=X509_STORE_new();X509_STORE_CTX *ctx=X509_STORE_CTX_new();char subject[33];
 bool ok=issuer && leaf && key && store && ctx && X509_check_ca(issuer)>0 && X509_check_ca(leaf)==0 &&
  X509_NAME_entry_count(X509_get_subject_name(leaf))==1 &&
  X509_NAME_get_text_by_NID(X509_get_subject_name(leaf),NID_commonName,subject,sizeof(subject))==32 && !strcmp(subject,node) &&
  X509_check_private_key(leaf,key)==1 && X509_STORE_add_cert(store,issuer)==1 &&
  X509_STORE_CTX_init(ctx,store,leaf,NULL)==1 && X509_verify_cert(ctx)==1;
 X509_STORE_CTX_free(ctx);X509_STORE_free(store);EVP_PKEY_free(key);X509_free(issuer);X509_free(leaf);BIO_free(a);BIO_free(b);BIO_free(k);return ok;
}
static bool station_matches(uc_value_t *spec,const char *ssid,const char *password) {
 const char *configured=text_field(spec,"config",512),*chosen=text_field(spec,"ssid",32),*bssid=text_field(spec,"bssid",17);
 if(!configured || !chosen || !ssid || strcmp(chosen,ssid) || !password || strlen(password)<8 || strlen(password)>63 || !bssid || strlen(bssid)!=17)return false;
 char expected[512];size_t used=0;const char prefix[]="network={\n\tssid=";memcpy(expected,prefix,sizeof(prefix)-1);used=sizeof(prefix)-1;
 for(size_t i=0;i<strlen(ssid);i++){unsigned char byte=ssid[i];if(byte<32 || byte==127)return false;snprintf(expected+used,3,"%02x",byte);used+=2;}
 for(unsigned i=0;i<17;i++)if(i%3==2 ? bssid[i]!=':' : !strchr("0123456789abcdef",bssid[i]))return false;
 int length=snprintf(expected+used,sizeof(expected)-used,"\n\tbssid=%s\n\tpsk=\"",bssid);if(length<0 || (size_t)length>=sizeof(expected)-used)return false;used+=(size_t)length;
 for(size_t i=0;i<strlen(password);i++){unsigned char byte=password[i];if(byte<32 || byte>126 || used+2>=sizeof(expected))return false;if(byte=='\\' || byte=='"')expected[used++]='\\';expected[used++]=byte;}
 const char suffix[]="\"\n\tkey_mgmt=WPA-PSK SAE\n}\n";if(used+sizeof(suffix)>sizeof(expected))return false;memcpy(expected+used,suffix,sizeof(suffix));
 return !strcmp(configured,expected);
}
/* Independent native cold guard. The UC gate also compares the actual UCI
 * snapshot before and after setup; this guard checks exact private identity,
 * key/leaf/pin/ref HMAC, original pristine journal and supplied raw snapshot.
 * It never authorizes recovery of a staged/applying/configured AP. */
static bool handoff_authorized(uc_vm_t *vm,uc_value_t *spec,uc_value_t *scope,json_object *identity) {
 uc_value_t *data=ucv_from_json(vm,identity),*e=ucv_object_get(data,"enrollment",NULL),*binding=ucv_object_get(data,"binding",NULL),
  *ref=ucv_object_get(data,"handoff",NULL),*j=NULL,*unsigned_ref=NULL;char *normalized=NULL,*message=NULL,*domain=NULL;bool ok=false;
 const char *key=text_field(scope,"key",RAW_LIMIT),*ca=text_field(scope,"network_ca",4096),*cert=text_field(scope,"cert",LIMIT),
  *join_ca=text_field(scope,"join_ca",4096),*snapshot=text_field(scope,"snapshot",RAW_LIMIT),*state=text_field(scope,"state",JOURNAL_LIMIT),
  *node=text_field(data,"id",32),*fp=text_field(data,"fingerprint",64),*epoch=text_field(e,"epoch",32),*ssid=text_field(e,"ssid",32),
  *password=text_field(e,"password",63),*code=text_field(e,"code",149),*address=text_field(binding,"address",15),*pin=text_field(binding,"ca_fingerprint",64),
  *network=text_field(binding,"network_id",32),*root=text_field(binding,"controller_id",32),*role=text_field(data,"role",7);int64_t value=0;
 bool has_state=false;ucv_object_get(scope,"state",&has_state);
 uc_value_t *cluster=ucv_object_get(data,"cluster_version",NULL);
 if(!data || !key || !ca || !cert || !join_ca || strcmp(join_ca,ca) || !snapshot || !has_state || !node || !fp || !role || strcmp(role,"ap") ||
  !device_key_matches(key,node,fp) || !number_field(data,"schema",1,1,&value) || ucv_type(ucv_object_get(data,"joining",NULL))!=UC_NULL ||
  ucv_type(ucv_object_get(data,"agent",NULL))!=UC_NULL || (ucv_type(cluster)!=UC_NULL && (ucv_type(cluster)!=UC_INTEGER || ucv_int64_get(cluster)!=0)) ||
  ucv_type(e)!=UC_OBJECT || ucv_type(ucv_object_get(e,"enabled",NULL))!=UC_BOOLEAN || !ucv_boolean_get(ucv_object_get(e,"enabled",NULL)) ||
  !hex_text(epoch,32) || !station_matches(spec,ssid,password) || !code || !address || !hex_text(pin,64) ||
  !hex_text(network,32) || !hex_text(root,32) || !strcmp(root,node) || ucv_object_length(binding)!=5 || !number_field(binding,"port",37901,37901,&value) ||
  !text_field(data,"network_id",32) || strcmp(text_field(data,"network_id",32),network) || !ca_pin(ca,pin) || !leaf_matches(ca,cert,key,node))goto done;
 uc_value_t *p=ucv_object_get(spec,"code",NULL);const char *pa=text_field(p,"address",15),*pf=text_field(p,"fingerprint",64),*pt=text_field(p,"token",64),*controller=text_field(spec,"controller",15);
 char expected_code[150];
 if(!pa || !pf || !hex_text(pt,64) || !controller || strcmp(controller,address) || strcmp(pa,address) || strcmp(pf,pin) ||
  snprintf(expected_code,sizeof(expected_code),"MM1:%s:%s:%s",address,pin,pt)<0 || strcmp(code,expected_code))goto done;
 normalized=ucv_to_jsonstring(vm,data);if(!normalized || strcmp(normalized,text_field(scope,"identity",RAW_LIMIT)))goto done;
 const char *fields[]={"ca","cert","epoch","identity","joining","journal","journal_base","key","request","schema","snapshot"};
 if(ucv_type(ref)!=UC_OBJECT || ucv_object_length(ref)!=12 || !number_field(ref,"schema",1,1,&value) ||
  !hex_text(text_field(ref,"request",32),32) || !hex_text(text_field(ref,"joining",64),64) ||
  !text_field(ref,"epoch",32) || strcmp(text_field(ref,"epoch",32),epoch) ||
  !raw_digest_equals(key,text_field(ref,"key",64)) || !raw_digest_equals(ca,text_field(ref,"ca",64)) ||
  !raw_digest_equals(cert,text_field(ref,"cert",64)) || !raw_digest_equals(snapshot,text_field(ref,"snapshot",64)))goto done;
 json_object *snapshot_json=parse_json(snapshot);if(!snapshot_json)goto done;json_object_put(snapshot_json);
 if(state){if(!raw_digest_equals(state,text_field(ref,"journal",64)))goto done;json_object *parsed=parse_json(state);
  if(!parsed)goto done;
  j=ucv_from_json(vm,parsed);json_object_put(parsed);
  char *serialized=ucv_to_jsonstring(vm,j);bool exact=serialized && !strcmp(serialized,state);free(serialized);if(!exact)goto done;
 }else{if(ucv_type(ucv_object_get(scope,"state",NULL))!=UC_NULL || ucv_type(ucv_object_get(ref,"journal",NULL))!=UC_NULL)goto done;
  j=ucv_object_new(vm);ucv_object_add(j,"schema",ucv_int64_new(1));ucv_object_add(j,"version",ucv_int64_new(0));ucv_object_add(j,"intent",NULL);
  ucv_object_add(j,"saved_intent",NULL);ucv_object_add(j,"paused",ucv_boolean_new(false));ucv_object_add(j,"owned",ucv_array_new(vm));ucv_object_add(j,"history",ucv_array_new(vm));ucv_object_add(j,"active",NULL);
 }
 uc_value_t *owned=ucv_object_get(j,"owned",NULL),*history=ucv_object_get(j,"history",NULL),*paused=ucv_object_get(j,"paused",NULL);
 if(!number_field(j,"schema",1,1,&value) || !number_field(j,"version",0,0,&value) || ucv_type(paused)!=UC_BOOLEAN || ucv_boolean_get(paused) ||
  ucv_type(owned)!=UC_ARRAY || ucv_array_length(owned) || ucv_type(history)!=UC_ARRAY || ucv_array_length(history) ||
  ucv_type(ucv_object_get(j,"intent",NULL))!=UC_NULL || ucv_type(ucv_object_get(j,"saved_intent",NULL))!=UC_NULL ||
  ucv_type(ucv_object_get(j,"active",NULL))!=UC_NULL || ucv_type(ucv_object_get(j,"restore_checkpoint",NULL))!=UC_NULL ||
  ucv_type(ucv_object_get(j,"first_handoff",NULL))!=UC_NULL)goto done;
 ucv_object_delete(j,"first_handoff");if(!serialized_digest_equals(vm,j,text_field(ref,"journal_base",64)))goto done;
 unsigned_ref=ucv_object_new(vm);
 for(unsigned i=0;i<11;i++){bool exists=false;uc_value_t *v=ucv_object_get(ref,fields[i],&exists);if(!exists)goto done;ucv_object_add(unsigned_ref,fields[i],ucv_get(v));}
 message=ucv_to_jsonstring(vm,unsigned_ref);char proof_key[65],proof[65];unsigned char mac[32];unsigned size=0;
 if(!message || asprintf(&domain,"mesh-manager/first-handoff/identity/v1\n%s",key)<0 || !digest_raw(domain,proof_key) ||
  !HMAC(EVP_sha256(),proof_key,64,(unsigned char *)message,strlen(message),mac,&size) || size!=32)goto done;
 for(unsigned i=0;i<32;i++)snprintf(proof+2*i,3,"%02x",mac[i]);
 if(!hex_text(text_field(ref,"proof",64),64) || strcmp(proof,text_field(ref,"proof",64)))goto done;
 const char *bare_hash=text_field(ref,"identity",64);char saved_hash[65];if(!hex_text(bare_hash,64))goto done;memcpy(saved_hash,bare_hash,65);
 ucv_object_delete(data,"handoff");ucv_object_delete(data,"agent");ucv_object_delete(data,"cluster_version");
 ok=serialized_digest_equals(vm,data,saved_hash);
 done:if(domain){memset(domain,0,strlen(domain));free(domain);}free(normalized);free(message);ucv_put(unsigned_ref);ucv_put(j);ucv_put(data);return ok;
}
static bool resume_authorized(uc_value_t *spec,uc_value_t *scope,json_object *identity) {
 json_object *enrollment=NULL,*joining=NULL,*invitation=NULL,*enabled=NULL,*protocol=NULL,*port=NULL,*enroll_port=NULL;
 if(!json_object_object_get_ex(identity,"enrollment",&enrollment) || !enrollment || json_object_get_type(enrollment)!=json_type_object ||
  !json_object_object_get_ex(enrollment,"enabled",&enabled) || !enabled || json_object_get_type(enabled)!=json_type_boolean || !json_object_get_boolean(enabled) ||
  !json_object_object_get_ex(identity,"joining",&joining) || !joining || json_object_get_type(joining)!=json_type_object ||
  !json_object_object_get_ex(joining,"invitation",&invitation) || !invitation || json_object_get_type(invitation)!=json_type_object)return false;
 const char *status=json_text(joining,"status",10),*ssid=json_text(enrollment,"ssid",32),*password=json_text(enrollment,"password",63),
  *code=json_text(enrollment,"code",149),*address=json_text(invitation,"address",15),*fingerprint=json_text(invitation,"fingerprint",64),
  *token=json_text(invitation,"token",64),*ca=json_text(invitation,"ca",4096),*node=json_text(identity,"id",32),*root=json_text(invitation,"controller_id",32);
 if(!status || (strcmp(status,"requesting") && strcmp(status,"pending")) || !ssid || !password || strlen(password)<8 ||
  !hex_text(json_text(enrollment,"epoch",32),32) || !hex_text(json_text(joining,"request_id",32),32) || !hex_text(json_text(joining,"secret",64),64) ||
  !hex_text(node,32) || !hex_text(root,32) || !strcmp(node,root) || !hex_text(json_text(invitation,"network_id",32),32) ||
  !address || !hex_text(fingerprint,64) || !hex_text(token,64) || !code || !ca_pin(ca,fingerprint))return false;
 if(!device_key_matches(text_field(scope,"key",RAW_LIMIT),node,json_text(identity,"fingerprint",64)))return false;
 if(!json_object_object_get_ex(invitation,"protocol",&protocol) || !protocol || json_object_get_type(protocol)!=json_type_int || json_object_get_int(protocol)!=1 ||
  !json_object_object_get_ex(invitation,"port",&port) || !port || json_object_get_type(port)!=json_type_int || json_object_get_int(port)!=37901 ||
  !json_object_object_get_ex(invitation,"enroll_port",&enroll_port) || !enroll_port || json_object_get_type(enroll_port)!=json_type_int || json_object_get_int(enroll_port)!=37902)return false;
 const char *controller=text_field(spec,"controller",15),*join_ca=text_field(scope,"join_ca",4096);
 uc_value_t *pin=ucv_object_get(spec,"code",NULL);const char *pa=text_field(pin,"address",15),*pf=text_field(pin,"fingerprint",64),*pt=text_field(pin,"token",64);
 char expected_code[150];int length=snprintf(expected_code,sizeof(expected_code),"MM1:%s:%s:%s",address,fingerprint,token);
 if(length<0 || (size_t)length>=sizeof(expected_code) || strcmp(code,expected_code) || !controller || strcmp(controller,address) ||
  !join_ca || strcmp(join_ca,ca) || !pa || strcmp(pa,address) || !pf || strcmp(pf,fingerprint) || !pt || strcmp(pt,token))return false;
 return station_matches(spec,ssid,password);
}
static bool standby_authorized(uc_vm_t *vm,uc_value_t *spec,uc_value_t *scope,json_object *initial) {
 const char *key=text_field(scope,"key",4096),*ca=text_field(scope,"network_ca",4096),*cert=text_field(scope,"cert",4096),
  *identity=text_field(scope,"identity",RAW_LIMIT),*state=text_field(scope,"state",JOURNAL_LIMIT),*snapshot=text_field(scope,"snapshot",RAW_LIMIT),
  *boot=text_field(scope,"boot",36),*config=text_field(spec,"config",512),*proof=text_field(spec,"proof",64);
 uc_value_t *data=ucv_from_json(vm,initial),*b=ucv_object_get(data,"binding",NULL),*actual=journal_read(vm,0),*journal=NULL;
 const char *actual_state=text_field(actual,"raw",JOURNAL_LIMIT),*node=text_field(data,"id",32),*role=text_field(data,"role",8),
  *pin=text_field(b,"ca_fingerprint",64),*address=text_field(b,"address",15),*controller=text_field(spec,"controller",15);
 json_object *parsed=state ? parse_json(state) : NULL;
 bool ok=false;char identity_hash[65],state_hash[65],snapshot_hash[65],config_hash[65],key_hash[65],*message=NULL;
 unsigned char signature[32];unsigned size=0;int64_t started=0;
 if(!key || !ca || !cert || !identity || !state || !snapshot || !boot || !config || !hex_text(proof,64) ||
  !actual_state || strcmp(state,actual_state) || !parsed || !node || !role || strcmp(role,"ap") ||
  ucv_object_get(data,"joining",NULL) || ucv_object_get(data,"handoff",NULL) || ucv_object_get(data,"departing",NULL) ||
  !pin || !address || !controller || strcmp(address,controller) || !ca_pin(ca,pin) || !leaf_matches(ca,cert,key,node))goto done;
 journal=ucv_from_json(vm,parsed);
 uc_value_t *paused=ucv_object_get(journal,"paused",NULL),*owned=ucv_object_get(journal,"owned",NULL),
  *a=ucv_object_get(journal,"active",NULL),*saved=ucv_object_get(journal,"saved_intent",NULL),*wifi=ucv_object_get(saved,"wifi",NULL),
  *disabled=ucv_object_get(a,"mesh_enabled",NULL);
 const char *kind=text_field(a,"kind",16),*status=text_field(a,"status",16),*ssid=text_field(wifi,"ssid",32),*password=text_field(wifi,"key",63);
 uc_value_t *points=ucv_object_get(data,"bootstrap",NULL);const char *target=text_field(spec,"bssid",17);bool pinned=false;
 if(ucv_type(points)==UC_ARRAY && ucv_array_length(points)<=8 && target)for(size_t n=0;n<ucv_array_length(points);n++) {
  uc_value_t *point=ucv_array_get(points,n);const char *point_ssid=text_field(point,"ssid",32),*point_bssid=text_field(point,"bssid",17);
  if(ssid && point_ssid && point_bssid && !strcmp(ssid,point_ssid) && !strcmp(target,point_bssid))pinned=true;
 }
 if(ucv_type(paused)!=UC_BOOLEAN || !ucv_boolean_get(paused) || ucv_type(owned)!=UC_ARRAY || ucv_array_length(owned) ||
  ucv_object_get(journal,"intent",NULL) || !kind || strcmp(kind,"release") || !status || strcmp(status,"committed") ||
  ucv_type(disabled)!=UC_BOOLEAN || ucv_boolean_get(disabled) || !ssid || !password || !pinned || !station_matches(spec,ssid,password) ||
  !number_field(spec,"started",1,INT64_MAX-SETUP,&started) || !digest_raw(key,key_hash) || !digest_raw(identity,identity_hash) ||
  !digest_raw(state,state_hash) || !digest_raw(snapshot,snapshot_hash) || !digest_raw(config,config_hash) ||
  asprintf(&message,"mesh-manager/standby/v1\n%s\n%s\n%s\n%s\n%s\n%lld\n",identity_hash,state_hash,snapshot_hash,config_hash,boot,(long long)started)<0 ||
  !HMAC(EVP_sha256(),key_hash,64,(const unsigned char *)message,strlen(message),signature,&size) || size!=32)goto done;
 char expected[65];for(unsigned i=0;i<32;i++)snprintf(expected+2*i,3,"%02x",signature[i]);
 ok=CRYPTO_memcmp(expected,proof,64)==0;
 done:OPENSSL_cleanse(signature,sizeof(signature));free(message);if(parsed)json_object_put(parsed);
 ucv_put(data);ucv_put(actual);ucv_put(journal);return ok;
}
static uc_value_t *begin_with_mode(uc_vm_t *vm,size_t nargs,unsigned mode) {
 uc_value_t *spec=uc_fn_arg(0),*scope=uc_fn_arg(1);int64_t phy,start;
 const char *config=text_field(spec,"config",512),*controller=text_field(spec,"controller",15),*boot=text_field(scope,"boot",36),*tag=text_field(scope,"tag",64);
 struct in_addr parsed={0};
 if(nargs!=2 || !config || !boot || !tag || !hex_text(tag,64) ||
  (mode==4 ? controller!=NULL : !controller || !ipv4(controller,&parsed,true)) ||
  !number_field(spec,"phy",0,999,&phy) || !number_field(spec,"started",1,INT64_MAX-SETUP,&start) ||
  (uint64_t)start>clock_ms() || clock_ms()>=(uint64_t)start+SETUP || !scope_matches(vm,scope))return failure(vm,"identity_error");
 const char *identity=text_field(scope,"identity",RAW_LIMIT);json_object *initial=identity ? parse_json(identity) : NULL,*role=NULL,*joining=NULL,*binding=NULL;
 bool unbound=initial && json_object_object_get_ex(initial,"role",&role) && role &&
  json_object_get_type(role)==json_type_string && !strcmp(json_object_get_string(role),"unbound");
 if(initial){json_object_object_get_ex(initial,"joining",&joining);json_object_object_get_ex(initial,"binding",&binding);}
 unbound=mode==3 ? initial && standby_authorized(vm,spec,scope,initial) : mode==2 ? initial && handoff_authorized(vm,spec,scope,initial) : unbound && !binding && (mode==1 ? resume_authorized(spec,scope,initial) : !joining);
 if(mode==4) {
  json_object *e=NULL,*enabled=NULL;
  if(initial)json_object_object_get_ex(initial,"enrollment",&e);
  if(e)json_object_object_get_ex(e,"enabled",&enabled);
  const char *ssid=json_text(e,"ssid",32),*password=json_text(e,"password",63),*epoch=json_text(e,"epoch",32);
  unbound=unbound && enabled && json_object_get_type(enabled)==json_type_boolean && json_object_get_boolean(enabled) &&
   ssid && password && hex_text(epoch,32) && !json_text(e,"code",149) && station_matches(spec,ssid,password);
 }
 json_object_put(initial);
 if(!unbound)return failure(vm,"identity_error");
 int parent=open(MESH_ONBOARD_ROOT,O_RDONLY|O_DIRECTORY|O_CLOEXEC);struct stat st;
 if(parent<0 || fstat(parent,&st) || !S_ISDIR(st.st_mode) || st.st_uid!=MESH_ONBOARD_UID || st.st_mode&0022){if(parent>=0)close(parent);return failure(vm,"runtime_unavailable");}
 if(mkdirat(parent,DIRECTORY,0700)){close(parent);return failure(vm,"already_active");}close(parent);
 struct actor *a=NULL;uc_value_t *object=ucv_resource_create_ex(vm,"mesh_onboard.actor",(void **)&a,0,sizeof(*a));
 if(!object)return failure(vm,"runtime_unavailable");
 a->dir=-1;a->control=-1;a->pending=-1;a->permit_fd=-1;a->phy=(int)phy;a->controller=parsed;
 a->discover=mode==4;
 a->deadline=(uint64_t)start+(a->discover ? 90000 : LIFETIME);a->setup_deadline=(uint64_t)start+SETUP;
 memcpy(a->origin_tag,tag,65);
 bool absent=false;a->dir=open_directory(&absent);
 unsigned char token[16];
 if(a->dir<0 || fstat(a->dir,&a->dir_stat) || !boot_id(a->boot) || strcmp(a->boot,boot) || !process_start(getpid(),a->owner_start) ||
  !entropy(token,sizeof(token)) || !entropy(a->mac,6))return object;
 for(unsigned i=0;i<16;i++)snprintf(a->generation+2*i,3,"%02x",token[i]);
 a->mac[0]=(a->mac[0]|2)&0xfe;
 int fd=openat(a->dir,CONFIG,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
 bool ok=fd>=0 && write_all(fd,config,strlen(config),budget(a,500));
 a->config_exists=fd>=0 && !fstat(fd,&a->config_stat) && safe_stat(&a->config_stat,false);
 ok=ok && a->config_exists;if(fd>=0 && close(fd))ok=false;
 if(!ok || !scope_matches(vm,scope) || !owned_socket(a))return object;
 uc_value_t *starting=ucv_object_new(vm);
 ucv_object_add(starting,"schema",ucv_int64_new(1));ucv_object_add(starting,"generation",ucv_string_new(a->generation));
 ucv_object_add(starting,"boot",ucv_string_new(a->boot));ucv_object_add(starting,"pid",ucv_int64_new(getpid()));
 ucv_object_add(starting,"start_ticks",ucv_string_new(a->owner_start));ucv_object_add(starting,"connected",ucv_boolean_new(false));
 ucv_object_add(starting,"status",ucv_string_new("starting"));ucv_object_add(starting,"scope_tag",ucv_get(ucv_object_get(scope,"tag",NULL)));
 ucv_object_add(starting,"session_scope_tag",ucv_string_new(a->origin_tag));
 ucv_object_add(starting,"observed",ucv_int64_new(clock_ms()));ucv_object_add(starting,"deadline",ucv_int64_new(a->deadline));
 char *starting_raw=ucv_to_jsonstring(vm,starting);ucv_put(starting);
 ok=starting_raw && scope_matches(vm,scope) && publish(a,starting_raw);free(starting_raw);
 if(!ok || requested_stop(a,0))return object;
 struct inventory_items local={0};bool available=inventory_dump(a,&local,true,budget(a,1500));
 for(size_t i=0;i<local.count;i++)free(local.item[i]);
 if(!available || requested_stop(a,0) || !scope_matches(vm,scope))return object;
 if(!create_link(a) || !link_current(a) ||
  !scope_matches(vm,scope))return object;
 char *baseline=inventory_read(a);
 // A newly created, still-down bootstrap link must be empty. Never adopt
 // addresses/routes installed by another actor during creation or UP.
 if(!baseline || *baseline){free(baseline);return object;}a->inventory=baseline;
 if(requested_stop(a,0) || !scope_matches(vm,scope) || !inventory_same(a) || !prepare_link(a) || requested_stop(a,0) ||
  !scope_matches(vm,scope) || !inventory_same(a) || !link_operation(a,false) || !inventory_same(a) || requested_stop(a,0))return object;
 char config_path[]=MESH_ONBOARD_ROOT "/" DIRECTORY "/" CONFIG;
 char *args[]={"/usr/sbin/wpa_supplicant","-i",IFACE,"-c",config_path,NULL};
 if(!scope_matches(vm,scope) || requested_stop(a,0) || clock_ms()>=a->setup_deadline)return object;
 a->wpa=spawn(args,-1,-1);return object;
}
static uc_value_t *begin_actor(uc_vm_t *vm,size_t nargs) {return begin_with_mode(vm,nargs,false);}
static uc_value_t *begin_resume_actor(uc_vm_t *vm,size_t nargs) {return begin_with_mode(vm,nargs,true);}
static uc_value_t *begin_handoff_actor(uc_vm_t *vm,size_t nargs) {return begin_with_mode(vm,nargs,2);}
static uc_value_t *begin_standby_actor(uc_vm_t *vm,size_t nargs) {return begin_with_mode(vm,nargs,3);}
static uc_value_t *begin_discover_actor(uc_vm_t *vm,size_t nargs) {return begin_with_mode(vm,nargs,4);}
static uc_value_t *actor_info(uc_vm_t *vm,size_t nargs) {
 struct actor *a=this_actor(vm);if(a && a->address_conflict)return failure(vm,"address_conflict");
 if(nargs || !a || a->dir<0 || a->wpa<=0 || clock_ms()>=(a->setup_complete ? a->deadline : a->setup_deadline) || !unchanged(a) || !link_current(a) || !inventory_same(a) || (a->lease_deadline && clock_ms()>=a->lease_deadline))return failure(vm,a && a->address_conflict ? "address_conflict" : "onboarding_failed");
 reap(a->wpa,&a->wpa_reaped,false);if(a->wpa_reaped)return failure(vm,"onboarding_failed");
 uc_value_t *o=ucv_object_new(vm);ucv_object_add(o,"schema",ucv_int64_new(1));
 ucv_object_add(o,"generation",ucv_string_new(a->generation));ucv_object_add(o,"boot",ucv_string_new(a->boot));
 ucv_object_add(o,"pid",ucv_int64_new(getpid()));ucv_object_add(o,"start_ticks",ucv_string_new(a->owner_start));
 ucv_object_add(o,"session_scope_tag",ucv_string_new(a->origin_tag));
 ucv_object_add(o,"ifindex",ucv_int64_new(a->ifindex));ucv_object_add(o,"phy",ucv_int64_new(a->phy));
 char mac[18];snprintf(mac,sizeof(mac),"%02x:%02x:%02x:%02x:%02x:%02x",a->mac[0],a->mac[1],a->mac[2],a->mac[3],a->mac[4],a->mac[5]);
 ucv_object_add(o,"mac",ucv_string_new(mac));ucv_object_add(o,"deadline",ucv_int64_new(a->lease_deadline && a->lease_deadline<a->deadline ? a->lease_deadline : a->deadline));
 if(a->controller.s_addr){char address[INET_ADDRSTRLEN];inet_ntop(AF_INET,&a->controller,address,sizeof(address));ucv_object_add(o,"controller",ucv_string_new(address));}
 return o;
}
static uc_value_t *dhcp_lease(uc_vm_t *vm,struct actor *a,uc_value_t *scope) {
 if(!a || a->dhcp || requested_stop(a,0) || !unchanged(a) || !link_current(a) || !scope_matches(vm,scope) || clock_ms()>=a->setup_deadline)return failure(vm,"identity_error");
 int pipes[2];if(pipe2(pipes,O_CLOEXEC|O_NONBLOCK))return failure(vm,"runtime_unavailable");
 char *args[]={"/sbin/udhcpc","-n","-q","-i",IFACE,"-t","8","-T","2","-s",DHCP,NULL};
 a->dhcp=spawn(args,pipes[1],-1);close(pipes[1]);uint64_t deadline=clock_ms()+20000;if(deadline>a->setup_deadline)deadline=a->setup_deadline;
 char frame[257]={0};size_t used=0;bool ok=false;
 while(a->dhcp>0 && clock_ms()<deadline && used<256) {
  if(requested_stop(a,0))break;
  struct pollfd p={.fd=pipes[0],.events=POLLIN};int remaining=(int)(deadline-clock_ms());if(remaining<=0)break;
  int polled=poll(&p,1,remaining>100 ? 100 : remaining);if(polled<0 && errno!=EINTR)break;
  if(polled>0){ssize_t n=read(pipes[0],frame+used,256-used);if(n>0){used+=(size_t)n;frame[used]=0;if(memchr(frame,'\n',used))break;}else if(n==0)break;}
  if(!scope_matches(vm,scope) || !unchanged(a) || !link_current(a))break;
  reap(a->wpa,&a->wpa_reaped,false);if(a->wpa_reaped)break;
 }
 close(pipes[0]);reap(a->dhcp,&a->dhcp_reaped,true);
 if(!a->dhcp_reaped)return failure(vm,"cleanup_conflict");
 if(used>=2 && used<=64 && frame[used-1]=='\n' && !memchr(frame,0,used)) {
  frame[used-1]=0;char *save=NULL,*ip=strtok_r(frame," ",&save),*mask=strtok_r(NULL," ",&save),*seconds=strtok_r(NULL," ",&save),*gateway=strtok_r(NULL," ",&save);
  struct in_addr subnet;uint32_t m=0,leased=0,root=ntohl(a->controller.s_addr);unsigned long lifetime=0;char *end=NULL;
  ok=ip && mask && seconds && !strtok_r(NULL," ",&save) && ipv4(ip,&a->lease,false) && inet_pton(AF_INET,mask,&subnet)==1;
  if(a->discover){ok=ok && gateway && ipv4(gateway,&a->controller,true);root=ntohl(a->controller.s_addr);}
  if(ok){m=ntohl(subnet.s_addr);leased=ntohl(a->lease.s_addr);lifetime=strtoul(seconds,&end,10);
   ok=m && ((~m+1)&~m)==0 && m!=UINT32_MAX && end && !*end && lifetime>=1 && lifetime<=86400 &&
    (leased&m)==(root&m) && leased!=root && (leased&~m)!=0 && (leased&~m)!=~m && (root&~m)!=0 && (root&~m)!=~m;
   a->lease_deadline=clock_ms()+lifetime*1000;}
 }
 if(!ok || requested_stop(a,0) || clock_ms()>=deadline || !scope_matches(vm,scope) || !unchanged(a) || !link_current(a) || !inventory_same(a))return failure(vm,"onboarding_failed");
 if(!address_operation(a,true))return failure(vm,"onboarding_failed");
 a->addr_created=true;
 if(!inventory_extend(a))return failure(vm,"cleanup_conflict");
 if(requested_stop(a,0) || !scope_matches(vm,scope) || !unchanged(a) || !link_current(a) || !route_operation(a,true))return failure(vm,"identity_error");
 a->route_created=true;
 if(!inventory_extend(a))return failure(vm,"cleanup_conflict");
 if(requested_stop(a,0) || !scope_matches(vm,scope) || clock_ms()>=a->setup_deadline)return failure(vm,"identity_error");
 uc_value_t *o=ucv_object_new(vm);char lease[INET_ADDRSTRLEN];inet_ntop(AF_INET,&a->lease,lease,sizeof(lease));
 ucv_object_add(o,"lease",ucv_string_new(lease));ucv_object_add(o,"lease_deadline",ucv_int64_new(a->lease_deadline));return o;
}
static uc_value_t *actor_dhcp(uc_vm_t *vm,size_t nargs) {
 return nargs==1 ? dhcp_lease(vm,this_actor(vm),uc_fn_arg(0)) : failure(vm,"identity_error");
}
static bool publish_observation(uc_vm_t *vm,struct actor *a,uc_value_t *value,uc_value_t *scope) {
 if(!a || ucv_type(value)!=UC_OBJECT || !scope_matches(vm,scope) || clock_ms()>=(a->setup_complete ? a->deadline : a->setup_deadline) ||
  !unchanged(a) || !link_current(a) || !inventory_same(a) || (a->lease_deadline && clock_ms()>=a->lease_deadline))return false;
 // Association is sampled between info() and publication. Recheck the actual
 // installed lease/local/Root routes and the direct WPA child after that
 // sample; an ACK or a preceding green observation is not current proof.
 reap(a->wpa,&a->wpa_reaped,false);
 bool connected=ucv_type(ucv_object_get(value,"connected",NULL))==UC_BOOLEAN && ucv_boolean_get(ucv_object_get(value,"connected",NULL));
 if(a->wpa<=0 || a->wpa_reaped || (connected && (!a->addr_created || !a->route_created)))return false;
 const char *tag=text_field(scope,"tag",64);if(!tag)return false;
 ucv_object_add(value,"scope_tag",ucv_string_new(tag));ucv_object_add(value,"observed",ucv_int64_new(clock_ms()));
 ucv_object_add(value,"session_scope_tag",ucv_string_new(a->origin_tag));
 char *raw=ucv_to_jsonstring(vm,value);
 bool ok=raw && scope_matches(vm,scope) && inventory_same(a) &&
  clock_ms()<(a->setup_complete ? a->deadline : a->setup_deadline) &&
  (!a->lease_deadline || clock_ms()<a->lease_deadline) && publish(a,raw);free(raw);
 if(ok && connected && a->addr_created && a->route_created && clock_ms()<a->setup_deadline)a->setup_complete=true;
 return ok;
}
static uc_value_t *actor_publish(uc_vm_t *vm,size_t nargs) {
 return ucv_boolean_new(nargs==2 && publish_observation(vm,this_actor(vm),uc_fn_arg(0),uc_fn_arg(1)));
}
static uc_value_t *actor_wait(uc_vm_t *vm,size_t nargs) {
 struct actor *a=this_actor(vm);int64_t delay=0;
 if(nargs!=1 || !a || ucv_type(uc_fn_arg(0))!=UC_INTEGER || (delay=ucv_int64_get(uc_fn_arg(0)))<0 || delay>3000 || !unchanged(a))return ucv_boolean_new(true);
 bool stopped=requested_stop(a,(int)delay) || clock_ms()>=a->deadline;
 if(stopped)return ucv_boolean_new(true);
 if(a->permit_raw){json_object *j=parse_json(a->permit_raw);uc_value_t *result=j ? ucv_from_json(vm,j) : NULL;json_object_put(j);return result ? result : ucv_boolean_new(false);}
 return ucv_boolean_new(false);
}
static uc_value_t *actor_permit_reply(uc_vm_t *vm,size_t nargs) {
 struct actor *a=this_actor(vm);bool accepted=nargs==1 && ucv_type(uc_fn_arg(0))==UC_BOOLEAN && ucv_boolean_get(uc_fn_arg(0));
 if(!a || a->permit_fd<0 || !a->permit_raw)return ucv_boolean_new(false);
 const char *reply=accepted ? "armed" : "rejected";
 bool ok=send(a->permit_fd,reply,strlen(reply),MSG_NOSIGNAL)==(ssize_t)strlen(reply);
 close(a->permit_fd);a->permit_fd=-1;free(a->permit_raw);a->permit_raw=NULL;return ucv_boolean_new(ok && accepted);
}
static bool directory_empty(int dir) {
 int copy=dup(dir);if(copy<0)return false;DIR *d=fdopendir(copy);if(!d){close(copy);return false;}
 rewinddir(d);bool empty=true;unsigned count=0;struct dirent *e;errno=0;
 while((e=readdir(d))!=NULL && count++<16)if(strcmp(e->d_name,".") && strcmp(e->d_name,"..")){empty=false;break;}
 if(errno || count>=16)empty=false;
 closedir(d);return empty;
}
static bool directory_known(struct actor *a) {
 int copy=dup(a->dir);if(copy<0)return false;DIR *d=fdopendir(copy);if(!d){close(copy);return false;}
 rewinddir(d);bool ok=true;unsigned count=0;struct dirent *e;errno=0;
 while((e=readdir(d))!=NULL && count++<16) {
  if(!strcmp(e->d_name,".") || !strcmp(e->d_name,".."))continue;
  if((a->state_exists && !strcmp(e->d_name,STATE)) || (a->config_exists && !strcmp(e->d_name,CONFIG)) ||
   (a->socket_exists && !strcmp(e->d_name,CONTROL)))continue;
  ok=false;break;
 }
 if(errno || count>=16)ok=false;
 closedir(d);return ok;
}
static bool cleanup_actor(struct actor *a) {
 if(!a || a->dir<0)return false;
 a->cleaning=true;a->cleanup_deadline=clock_ms()+12000;
 reap(a->dhcp,&a->dhcp_reaped,true);reap(a->wpa,&a->wpa_reaped,true);
 // Complete preflight rejects external address/route/master changes before
 // deleting any network object. Uncertain kernel outcomes remain conflicts.
 if((a->wpa>0 && !a->wpa_reaped) || (a->dhcp>0 && !a->dhcp_reaped) || !unchanged(a) || !directory_known(a) || (a->link_requested && a->ifindex<=0))return false;
 if(a->ifindex && (!a->inventory || !inventory_same(a) || !unchanged(a) || !inventory_same(a) || !link_operation(a,true)))return false;
 a->ifindex=0;
 if(!unchanged(a))return false;
 if(a->state_exists && (!path_same(a->dir,STATE,&a->state_stat,false) || unlinkat(a->dir,STATE,0)))return false;
 a->state_exists=false;
 if(a->config_exists && (!path_same(a->dir,CONFIG,&a->config_stat,false) || unlinkat(a->dir,CONFIG,0)))return false;
 a->config_exists=false;
 if(a->socket_exists && (!path_same(a->dir,CONTROL,&a->socket_stat,false) || unlinkat(a->dir,CONTROL,0)))return false;
 a->socket_exists=false;
 if(!directory_same(a->dir) || !directory_empty(a->dir))return false;
 int parent=open(MESH_ONBOARD_ROOT,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
 bool ok=parent>=0 && directory_same(a->dir) && unlinkat(parent,DIRECTORY,AT_REMOVEDIR)==0;
 if(parent>=0)close(parent);
 return ok;
}
static uc_value_t *actor_close(uc_vm_t *vm,size_t nargs) {
 struct actor *a=this_actor(vm);if(nargs || !a)return failure(vm,"cleanup_conflict");
 bool ok=cleanup_actor(a);
 if(!ok && a->last_raw && unchanged(a)) {
  json_object *terminal=parse_json(a->last_raw);
  if(terminal){json_object_object_add(terminal,"connected",json_object_new_boolean(false));
   json_object_object_add(terminal,"error",json_object_new_string("cleanup_conflict"));
   publish(a,json_object_to_json_string_ext(terminal,JSON_C_TO_STRING_PLAIN));json_object_put(terminal);}
 }
 if(a->pending>=0){const char *reply=ok ? "stopped" : "cleanup_conflict";send(a->pending,reply,strlen(reply),MSG_NOSIGNAL);close(a->pending);a->pending=-1;}
 return ok ? ucv_boolean_new(true) : failure(vm,"cleanup_conflict");
}
static void actor_free(void *data) {
 struct actor *a=data;if(!a)return;
 reap(a->dhcp,&a->dhcp_reaped,true);reap(a->wpa,&a->wpa_reaped,true);
 if(a->pending>=0)close(a->pending);
 if(a->permit_fd>=0)close(a->permit_fd);
 free(a->permit_raw);
 if(a->control>=0)close(a->control);
 if(a->dir>=0)close(a->dir);
 free(a->last_raw);free(a->inventory);
}
static uc_value_t *read_observation(uc_vm_t *vm,size_t nargs) {
 if(nargs)return failure(vm,"runtime_unavailable");
 bool missing=false;int dir=open_directory(&missing);if(dir<0){struct stat link;
  return missing && lstat("/sys/class/net/" IFACE,&link)<0 && errno==ENOENT ? NULL : failure(vm,"runtime_unavailable");}
 struct stat state_st;char *raw=read_file(dir,STATE,LIMIT,&state_st);uc_value_t *result=NULL;
 if(raw && directory_same(dir)){json_object *json=parse_json(raw);if(json){result=ucv_from_json(vm,json);json_object_put(json);}}
 free(raw);if(!result){close(dir);return failure(vm,"runtime_unavailable");}
 const char *boot=text_field(result,"boot",36),*tag=text_field(result,"scope_tag",64),*ticks=text_field(result,"start_ticks",20),*mac=text_field(result,"mac",17),*generation=text_field(result,"generation",32);
 int64_t pid=0,index=0,phy=0,observed=0,deadline=0,format=0;char actual_ticks[21],actual_boot[37];struct stat control_st;
 bool owner=number_field(result,"schema",1,1,&format) && boot && generation && hex_text(generation,32) && ticks && number_field(result,"pid",1,INT_MAX,&pid) &&
  boot_id(actual_boot) && !strcmp(boot,actual_boot) && process_start((pid_t)pid,actual_ticks) && !strcmp(ticks,actual_ticks) &&
  !fstatat(dir,CONTROL,&control_st,AT_SYMLINK_NOFOLLOW) && S_ISSOCK(control_st.st_mode) &&
  control_st.st_uid==MESH_ONBOARD_UID && !(control_st.st_mode&0077) && control_st.st_nlink==1 &&
  directory_same(dir) && path_same(dir,STATE,&state_st,false) && path_same(dir,CONTROL,&control_st,false);
 struct actor current={0};bool ok=
  boot && tag && ticks && mac && number_field(result,"pid",1,INT_MAX,&pid) &&
  number_field(result,"ifindex",1,INT_MAX,&index) && number_field(result,"phy",0,999,&phy) &&
  number_field(result,"observed",1,INT64_MAX,&observed) && number_field(result,"deadline",1,INT64_MAX,&deadline) &&
  process_start((pid_t)pid,actual_ticks) && !strcmp(ticks,actual_ticks);
 current.ifindex=(int)index;current.phy=(int)phy;
 unsigned values[6];if(!mac || sscanf(mac,"%2x:%2x:%2x:%2x:%2x:%2x",&values[0],&values[1],&values[2],&values[3],&values[4],&values[5])!=6)ok=false;
 else for(unsigned i=0;i<6;i++)current.mac[i]=(unsigned char)values[i];
 uint64_t now=clock_ms();ok=ok && now>=(uint64_t)observed && now-(uint64_t)observed<=FRESH && now<(uint64_t)deadline && link_current(&current) &&
  directory_same(dir) && path_same(dir,STATE,&state_st,false);close(dir);
 ucv_object_add(result,"owner_verified",ucv_boolean_new(owner));
 ucv_object_add(result,"resources_verified",ucv_boolean_new(ok));
 ucv_object_add(result,"verified",ucv_boolean_new(ok && scope_tag_matches(vm,tag,boot)));
 ucv_object_add(result,"now",ucv_int64_new(now));return result;
}
static uc_value_t *native_now(uc_vm_t *vm,size_t nargs) {(void)vm;return nargs ? NULL : ucv_int64_new(clock_ms());}
static uc_value_t *launch_worker(uc_vm_t *vm,size_t nargs) {
 uc_value_t *spec=uc_fn_arg(0);char *raw=NULL;int input[2]={-1,-1},output[2]={-1,-1};uc_value_t *result=NULL;int64_t started=0;
 if(nargs!=1 || ucv_type(spec)!=UC_OBJECT || !number_field(spec,"started",1,INT64_MAX-SETUP,&started) ||
  (uint64_t)started>clock_ms() || clock_ms()>=(uint64_t)started+SETUP || !(raw=ucv_to_jsonstring(vm,spec)) || strlen(raw)>2*RAW_LIMIT+4*LIMIT)goto done;
 if(socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0,input) || pipe2(output,O_CLOEXEC|O_NONBLOCK))goto done;
 pid_t child=fork();if(child==0){
  close(input[1]);close(output[0]);if(setsid()<0)_exit(127);
  pid_t detached=fork();if(detached<0)_exit(127);if(detached>0)_exit(0);
  if(signal(SIGPIPE,SIG_IGN)==SIG_ERR || dup2(input[0],0)<0 || dup2(output[1],1)<0 || fcntl(0,F_SETFL,0))_exit(127);
  int null=open("/dev/null",O_WRONLY);if(null<0 || dup2(null,2)<0)_exit(127);
  close(3);if(close_inherited(-1,-1))_exit(127);
  char *args[]={"/usr/bin/ucode",WORKER,NULL},*env[]={"PATH=/usr/sbin:/usr/bin:/sbin:/bin",NULL};execve(args[0],args,env);_exit(127);
 }
 close(input[0]);input[0]=-1;close(output[1]);output[1]=-1;if(child<0)goto done;
 uint64_t deadline=(uint64_t)started+SETUP;int status;pid_t waited;
 struct timespec pause={0,10000000};
 do{waited=waitpid(child,&status,WNOHANG);if(waited==0)nanosleep(&pause,NULL);}while((waited==0 || (waited<0 && errno==EINTR)) && clock_ms()<deadline);
 if(waited!=child){bool reaped=false;reap(child,&reaped,true);goto done;}
 if(!write_all(input[1],raw,strlen(raw),deadline))goto done;
 close(input[1]);input[1]=-1;
 char buffer[LIMIT+1];size_t used=0;
 while(clock_ms()<deadline && used<LIMIT){struct pollfd p={.fd=output[0],.events=POLLIN};int remaining=(int)(deadline-clock_ms());if(remaining<=0 || poll(&p,1,remaining)<=0)break;
  ssize_t n=read(output[0],buffer+used,LIMIT-used);if(n<=0){if(n<0 && (errno==EINTR || errno==EAGAIN))continue;break;}used+=(size_t)n;if(memchr(buffer,'\n',used))break;}
 buffer[used]=0;if(!used || used==LIMIT || clock_ms()>=deadline)goto done;
 json_object *json=parse_json(buffer);if(json){result=ucv_from_json(vm,json);json_object_put(json);}
 done:for(unsigned i=0;i<2;i++){if(input[i]>=0)close(input[i]);if(output[i]>=0)close(output[i]);}if(raw){memset(raw,0,strlen(raw));free(raw);}return result ? result : failure(vm,"onboarding_failed");
}
static uc_value_t *stop_with_generation(uc_vm_t *vm,const char *expected,uc_value_t *handle) {
 bool missing=false;int dir=open_directory(&missing);
 if(dir<0){struct stat link;
  return missing && lstat("/sys/class/net/" IFACE,&link)<0 && errno==ENOENT ? ucv_boolean_new(true) : failure(vm,"cleanup_conflict");}
 struct stat state_st,socket_st;char *raw=read_file(dir,STATE,LIMIT,&state_st);uc_value_t *state=NULL,*result=NULL;
 if(raw){json_object *j=parse_json(raw);if(j){state=ucv_from_json(vm,j);json_object_put(j);}}
 const char *generation=text_field(state,"generation",32),*start=text_field(state,"start_ticks",20);int64_t pid=0;
 int fd=-1;
 if(!generation || strlen(generation)!=32 || (expected && strcmp(expected,generation)) || !start || !number_field(state,"pid",1,INT_MAX,&pid) ||
  fstatat(dir,CONTROL,&socket_st,AT_SYMLINK_NOFOLLOW) || !S_ISSOCK(socket_st.st_mode) || socket_st.st_uid!=MESH_ONBOARD_UID || socket_st.st_mode&0077 || socket_st.st_nlink!=1)goto done;
 if(handle) {
  const char *boot=text_field(state,"boot",36),*captured_boot=text_field(handle,"boot",36),*captured_ticks=text_field(handle,"start_ticks",20);char actual_boot[37];int64_t captured_pid=0;
  if(!boot || !captured_boot || !captured_ticks || !boot_id(actual_boot) || strcmp(boot,actual_boot) || strcmp(boot,captured_boot) ||
   strcmp(start,captured_ticks) || !number_field(handle,"pid",1,INT_MAX,&captured_pid) || pid!=captured_pid)goto done;
 }
 fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0);struct sockaddr_un address={.sun_family=AF_UNIX};
 if(fd<0 || snprintf(address.sun_path,sizeof(address.sun_path),MESH_ONBOARD_ROOT "/" DIRECTORY "/" CONTROL)>=(int)sizeof(address.sun_path) || connect(fd,(void *)&address,sizeof(address)))goto done;
 struct ucred peer;socklen_t size=sizeof(peer);char ticks[21];
 if(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size) || size!=sizeof(peer) || peer.uid!=MESH_ONBOARD_UID || peer.pid!=pid ||
  !process_start(peer.pid,ticks) || strcmp(ticks,start) || !directory_same(dir) || !path_same(dir,STATE,&state_st,false) || !path_same(dir,CONTROL,&socket_st,false))goto done;
 if(send(fd,generation,32,MSG_NOSIGNAL)!=32)goto done;
 struct pollfd p={.fd=fd,.events=POLLIN};if(poll(&p,1,12000)<=0)goto done;
 char reply[32];ssize_t n=recv(fd,reply,sizeof(reply),0);if(n==7 && !memcmp(reply,"stopped",7))result=ucv_boolean_new(true);
 done:if(fd>=0)close(fd);free(raw);ucv_put(state);close(dir);return result ? result : failure(vm,"cleanup_conflict");
}
static uc_value_t *stop_worker(uc_vm_t *vm,size_t nargs) {return nargs ? failure(vm,"cleanup_conflict") : stop_with_generation(vm,NULL,NULL);}
static uc_value_t *stop_generation(uc_vm_t *vm,size_t nargs) {
 uc_value_t *value=uc_fn_arg(0);const char *generation=ucv_type(value)==UC_STRING ? ucv_string_get(value) : NULL;
 uc_value_t *handle=nargs==2 ? uc_fn_arg(1) : NULL;
 return (nargs==1 || (nargs==2 && ucv_type(handle)==UC_OBJECT)) && hex_text(generation,32) ? stop_with_generation(vm,generation,handle) : failure(vm,"cleanup_conflict");
}
static uc_value_t *grant_permit(uc_vm_t *vm,size_t nargs) {
 uc_value_t *frame=uc_fn_arg(0),*scope=uc_fn_arg(1);int64_t timeout=0;
 const char *generation=text_field(frame,"generation",32);char *payload=NULL;
 if(nargs!=3 || !generation || !hex_text(generation,32) || !number_field(frame,"schema",1,1,&timeout) ||
  ucv_type(uc_fn_arg(2))!=UC_INTEGER || (timeout=ucv_int64_get(uc_fn_arg(2)))<1 || timeout>8000 ||
  !scope_matches(vm,scope) || !(payload=ucv_to_jsonstring(vm,frame)) || strlen(payload)>=PERMIT_LIMIT){free(payload);return failure(vm,"identity_error");}
 uint64_t deadline=clock_ms()+(uint64_t)timeout;bool missing=false;int dir=open_directory(&missing),fd=-1;uc_value_t *state=NULL,*result=NULL;
 struct stat state_st,socket_st;char *raw=dir>=0 ? read_file(dir,STATE,LIMIT,&state_st) : NULL;
 if(raw){json_object *j=parse_json(raw);if(j){state=ucv_from_json(vm,j);json_object_put(j);}}
 const char *actual_generation=text_field(state,"generation",32),*start=text_field(state,"start_ticks",20),*origin=text_field(state,"session_scope_tag",64),*expected_origin=text_field(frame,"origin_tag",64);
 int64_t pid=0;
 if(dir<0 || !actual_generation || strcmp(generation,actual_generation) || !origin || !expected_origin || strcmp(origin,expected_origin) ||
  !start || !number_field(state,"pid",1,INT_MAX,&pid) || fstatat(dir,CONTROL,&socket_st,AT_SYMLINK_NOFOLLOW) ||
  !S_ISSOCK(socket_st.st_mode) || socket_st.st_uid!=MESH_ONBOARD_UID || socket_st.st_mode&0077 || socket_st.st_nlink!=1)goto done;
 fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0);struct sockaddr_un address={.sun_family=AF_UNIX};
 if(fd<0 || snprintf(address.sun_path,sizeof(address.sun_path),MESH_ONBOARD_ROOT "/" DIRECTORY "/" CONTROL)>=(int)sizeof(address.sun_path) || connect(fd,(void *)&address,sizeof(address)))goto done;
 struct ucred peer;socklen_t size=sizeof(peer);char ticks[21];
 if(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size) || size!=sizeof(peer) || peer.uid!=MESH_ONBOARD_UID || peer.pid!=pid ||
  !process_start(peer.pid,ticks) || strcmp(ticks,start) || !directory_same(dir) || !path_same(dir,STATE,&state_st,false) ||
  !path_same(dir,CONTROL,&socket_st,false) || !scope_matches(vm,scope) || clock_ms()>=deadline)goto done;
 size_t bytes=strlen(payload);if(send(fd,payload,bytes,MSG_NOSIGNAL)!=(ssize_t)bytes)goto done;
 struct pollfd p={.fd=fd,.events=POLLIN};int remaining=(int)(deadline-clock_ms());if(remaining<=0 || poll(&p,1,remaining)<=0 || clock_ms()>=deadline)goto done;
 char reply[16];ssize_t n=recv(fd,reply,sizeof(reply),MSG_DONTWAIT);
 if(n==5 && !memcmp(reply,"armed",5) && scope_matches(vm,scope) && directory_same(dir) && path_same(dir,CONTROL,&socket_st,false) && clock_ms()<deadline)result=ucv_boolean_new(true);
 done:if(fd>=0)close(fd);free(raw);free(payload);ucv_put(state);if(dir>=0)close(dir);return result ? result : failure(vm,"identity_error");
}
static const uc_function_list_t actor_functions[]={
 {"info",actor_info},{"dhcp",actor_dhcp},{"publish",actor_publish},{"wait",actor_wait},{"permit_reply",actor_permit_reply},{"close",actor_close}
};
static const uc_function_list_t functions[]={
 {"scope",scope_read},{"journal",journal_read},{"now",native_now},{"begin",begin_actor},{"begin_resume",begin_resume_actor},{"begin_handoff",begin_handoff_actor},{"begin_standby",begin_standby_actor},{"begin_discover",begin_discover_actor},{"read",read_observation},{"launch",launch_worker},{"stop",stop_worker},{"stop_generation",stop_generation},{"permit",grant_permit}
};
void uc_module_init(uc_vm_t *vm,uc_value_t *scope) {
 uc_type_declare(vm,"mesh_onboard.actor",actor_functions,actor_free);uc_function_list_register(scope,functions);
}
