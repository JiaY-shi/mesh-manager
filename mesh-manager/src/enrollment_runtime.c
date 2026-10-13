// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <ucode/module.h>

#ifndef MESH_ENROLLMENT_RUNTIME_ROOT
#define MESH_ENROLLMENT_RUNTIME_ROOT "/var/run"
#endif
#ifndef MESH_ENROLLMENT_RUNTIME_UID
#define MESH_ENROLLMENT_RUNTIME_UID 0
#endif
#define DIRECTORY "mesh-manager-enrollment"
#define STATE "state.json"
#define TEMP "state.new"
#define KEY "key"
#define LIMIT 16384
#define RETRIES 8

static bool safe_fd(int fd, bool directory, bool private)
{
	struct stat st;
	return !fstat(fd, &st) && st.st_uid == MESH_ENROLLMENT_RUNTIME_UID &&
	       !(st.st_mode & (private ? 0077 : 0022)) &&
	       (directory ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode) && st.st_nlink == 1);
}

static bool same_stat(const struct stat *a, const struct stat *b)
{
	return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
	       a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
	       a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

/* All paths are fixed. /var/run may be the standard system symlink; only the
 * trusted parent is followed, never the private directory or its objects. */
static int directory(bool create, bool *missing)
{
	int parent = open(MESH_ENROLLMENT_RUNTIME_ROOT, O_RDONLY | O_DIRECTORY | O_CLOEXEC), fd = -1;
	struct stat a, b;
	*missing = false;
	if (parent < 0 || !safe_fd(parent, true, false)) goto done;
	fd = openat(parent, DIRECTORY, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0 && errno == ENOENT) {
		if (!create) { *missing = true; goto done; }
		if (mkdirat(parent, DIRECTORY, 0700) && errno != EEXIST) goto done;
		fd = openat(parent, DIRECTORY, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	}
	if (fd >= 0 && (!safe_fd(fd, true, true) || fstat(fd, &a) ||
	    fstatat(parent, DIRECTORY, &b, AT_SYMLINK_NOFOLLOW) ||
	    a.st_dev != b.st_dev || a.st_ino != b.st_ino)) { close(fd); fd = -1; }
 done:
	if (parent >= 0) close(parent);
	return fd;
}

static bool directory_current(int dir)
{
 int parent=open(MESH_ENROLLMENT_RUNTIME_ROOT,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
 struct stat a,b;
 bool ok=parent>=0 && safe_fd(parent,true,false) && safe_fd(dir,true,true) &&
  !fstat(dir,&a) && !fstatat(parent,DIRECTORY,&b,AT_SYMLINK_NOFOLLOW) &&
  a.st_dev==b.st_dev && a.st_ino==b.st_ino;
 if(parent>=0 && close(parent))ok=false;
 return ok;
}

static char *read_file(int dir, const char *name, size_t maximum, size_t *length, bool *missing, struct stat *snapshot)
{
	int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	struct stat before, after, path;
	char *data = NULL, extra;
	size_t used = 0;
	unsigned retries = 0;
	ssize_t n;
	*missing = fd < 0 && errno == ENOENT;
	if (fd < 0 || !safe_fd(fd, false, true) || fstat(fd, &before) ||
	    before.st_size <= 0 || before.st_size > (off_t)maximum) goto done;
	data = malloc((size_t)before.st_size + 1);
	if (!data) goto done;
	while (used < (size_t)before.st_size) {
		n = read(fd, data + used, (size_t)before.st_size - used);
		if (n < 0 && errno == EINTR && retries++ < RETRIES) continue;
		if (n <= 0) goto fail;
		used += (size_t)n;
	}
	retries = 0;
	do { n = read(fd, &extra, 1); } while (n < 0 && errno == EINTR && retries++ < RETRIES);
	if (n != 0 || !safe_fd(fd, false, true) || fstat(fd, &after) ||
	    fstatat(dir, name, &path, AT_SYMLINK_NOFOLLOW) || !same_stat(&before, &after) ||
	    !same_stat(&after, &path) || memchr(data, 0, used)) goto fail;
	data[used] = 0; *length = used; if (snapshot) *snapshot = after;
	goto done;
 fail:
	memset(data, 0, used); free(data); data = NULL;
 done:
	if (fd >= 0 && close(fd)) { free(data); data = NULL; }
	return data;
}

static bool path_snapshot(int dir,const char *name,const struct stat *expected,bool absent)
{
 struct stat st;
 int result=fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW);
 if(absent)return result<0 && errno==ENOENT;
 return !result && S_ISREG(st.st_mode) && st.st_uid==MESH_ENROLLMENT_RUNTIME_UID &&
  !(st.st_mode&0077) && st.st_nlink==1 && same_stat(expected,&st);
}

static bool write_all(int fd, const char *data, size_t length)
{
	size_t used = 0;
	unsigned retries = 0;
	while (used < length) {
		ssize_t n = write(fd, data + used, length - used);
		if (n < 0 && errno == EINTR && retries++ < RETRIES) continue;
		if (n <= 0) return false;
		used += (size_t)n;
	}
	return true;
}

static bool hex64(const char *s, size_t length)
{
	if (length != 64) return false;
	for (size_t i = 0; i < length; i++)
		if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
	return true;
}

static bool generate_key(int dir)
{
	unsigned char bytes[32];
	char value[65];
	unsigned retries = 0;
	size_t used = 0;
	int fd;
	bool ok;
	while (used < sizeof(bytes)) {
		ssize_t n = getrandom(bytes + used, sizeof(bytes) - used, GRND_NONBLOCK);
		if (n < 0 && errno == EINTR && retries++ < RETRIES) continue;
		if (n <= 0) return false;
		used += (size_t)n;
	}
	for (size_t i = 0; i < sizeof(bytes); i++) snprintf(value + i * 2, 3, "%02x", bytes[i]);
	memset(bytes, 0, sizeof(bytes));
	fd = openat(dir, KEY, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) return false;
	ok = safe_fd(fd, false, true) && write_all(fd, value, 64);
	struct stat partial,current;
	char actual[64];
	bool ours=false;
	if(!ok && safe_fd(fd,false,true) && !fstat(fd,&partial) && partial.st_size>=0 && partial.st_size<64){
		ssize_t n;unsigned tries=0;
		do{n=pread(fd,actual,(size_t)partial.st_size,0);}while(n<0 && errno==EINTR && tries++<RETRIES);
		ours=n==partial.st_size && !memcmp(actual,value,(size_t)partial.st_size);
	}
	if(close(fd))ok=false;
	// Remove only this call's exact incomplete new inode and bytes. Historical
	// or externally replaced keys are preserved; a complete key can be reread
	// after an uncertain close without regenerating authorization material.
	if(ours && directory_current(dir) && !fstatat(dir,KEY,&current,AT_SYMLINK_NOFOLLOW) && same_stat(&partial,&current))
		(void)unlinkat(dir,KEY,0);
	memset(actual,0,sizeof(actual));memset(value,0,sizeof(value));
	return ok;
}

static uc_value_t *storage_error(uc_vm_t *vm)
{
	uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "runtime_unavailable: Unsafe or unavailable enrollment progress storage");
	return NULL;
}

static void stamp(char out[512], const struct stat *state, bool absent, const struct stat *key)
{
 snprintf(out,512,"%d:%llu:%llu:%lld:%ld:%lld:%ld:%lld:%llu:%llu:%lld:%ld:%lld:%ld:%lld",absent,
  absent ? 0 : (unsigned long long)state->st_dev,absent ? 0 : (unsigned long long)state->st_ino,
  absent ? 0 : (long long)state->st_mtim.tv_sec,absent ? 0 : state->st_mtim.tv_nsec,
  absent ? 0 : (long long)state->st_ctim.tv_sec,absent ? 0 : state->st_ctim.tv_nsec,
  absent ? 0 : (long long)state->st_size,
  (unsigned long long)key->st_dev,(unsigned long long)key->st_ino,
  (long long)key->st_mtim.tv_sec,key->st_mtim.tv_nsec,(long long)key->st_ctim.tv_sec,key->st_ctim.tv_nsec,(long long)key->st_size);
}

static uc_value_t *read_runtime(uc_vm_t *vm, size_t nargs)
{
 if(nargs>1 || (nargs==1 && ucv_type(uc_fn_arg(0))!=UC_BOOLEAN))return storage_error(vm);
 bool create=nargs==1 && ucv_boolean_get(uc_fn_arg(0));
 bool missing,state_missing,key_missing;
 size_t state_size=0,key_size=0;
 struct stat state_stat={0},key_stat={0};char signature[512];
 int dir=directory(create,&missing);
 char *raw=NULL,*key=NULL;
 uc_value_t *result=NULL;
 if(dir<0)return missing ? NULL : storage_error(vm);
 raw=read_file(dir,STATE,LIMIT,&state_size,&state_missing,&state_stat);
 key=read_file(dir,KEY,64,&key_size,&key_missing,&key_stat);
 if((!raw && !state_missing) || (!key && !key_missing))goto done;
 if(!key && create && state_missing && key_missing){
  if(!generate_key(dir))goto done;
  key=read_file(dir,KEY,64,&key_size,&key_missing,&key_stat);
 }
 if(!key || !hex64(key,key_size) || !path_snapshot(dir,STATE,&state_stat,state_missing) ||
  !path_snapshot(dir,KEY,&key_stat,false) || !directory_current(dir))goto done;
 stamp(signature,&state_stat,state_missing,&key_stat);
 result=ucv_object_new(vm);
 ucv_object_add(result,"raw",raw ? ucv_string_new_length(raw,state_size) : NULL);
 ucv_object_add(result,"key",ucv_string_new_length(key,key_size));
 ucv_object_add(result,"stamp",ucv_string_new(signature));
 done:
 if(key){memset(key,0,key_size);free(key);}free(raw);
 if(close(dir)){ucv_put(result);result=NULL;}
 return result ? result : storage_error(vm);
}

static bool matching(int dir,uc_value_t *expected)
{
 bool absent,key_absent,found;size_t size=0,key_size=0;
 struct stat state_stat={0},key_stat={0};char signature[512];
 char *raw=read_file(dir,STATE,LIMIT,&size,&absent,&state_stat);
 char *key=read_file(dir,KEY,64,&key_size,&key_absent,&key_stat);
 uc_value_t *old_raw=ucv_object_get(expected,"raw",&found),*old_key=ucv_object_get(expected,"key",NULL),
  *old_stamp=ucv_object_get(expected,"stamp",NULL);
 bool ok=false;
 if(!found || (!raw && !absent) || !key || !hex64(key,key_size))goto done;
 stamp(signature,&state_stat,absent,&key_stat);
 ok=(absent ? ucv_type(old_raw)==UC_NULL : ucv_type(old_raw)==UC_STRING &&
  ucv_string_length(old_raw)==size && !memcmp(ucv_string_get(old_raw),raw,size)) &&
  ucv_type(old_key)==UC_STRING && ucv_string_length(old_key)==key_size && !memcmp(ucv_string_get(old_key),key,key_size) &&
  ucv_type(old_stamp)==UC_STRING && ucv_string_length(old_stamp)==strlen(signature) &&
  !memcmp(ucv_string_get(old_stamp),signature,strlen(signature)) &&
  path_snapshot(dir,STATE,&state_stat,absent) && path_snapshot(dir,KEY,&key_stat,false) && directory_current(dir);
 done:
 free(raw);if(key){memset(key,0,key_size);free(key);}return ok;
}

static uc_value_t *publish(uc_vm_t *vm,size_t nargs)
{
 uc_value_t *v=uc_fn_arg(0),*expected=uc_fn_arg(1);
 bool missing,ok=false;int dir=-1,fd=-1;struct stat st,staged;
 if(nargs!=2 || ucv_type(expected)!=UC_OBJECT || ucv_object_length(expected)!=3 ||
  ucv_type(v)!=UC_STRING || !ucv_string_length(v) || ucv_string_length(v)>LIMIT ||
  memchr(ucv_string_get(v),0,ucv_string_length(v)))return storage_error(vm);
 dir=directory(false,&missing);if(dir<0)return storage_error(vm);
 if(!matching(dir,expected))goto done;
 if(!fstatat(dir,TEMP,&st,AT_SYMLINK_NOFOLLOW)){
  if(!S_ISREG(st.st_mode) || st.st_uid!=MESH_ENROLLMENT_RUNTIME_UID || st.st_mode&0077 ||
   st.st_nlink!=1 || st.st_size>LIMIT || unlinkat(dir,TEMP,0))goto done;
 }else if(errno!=ENOENT)goto done;
 fd=openat(dir,TEMP,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
 if(fd<0 || !safe_fd(fd,false,true))goto done;
 ok=write_all(fd,ucv_string_get(v),ucv_string_length(v)) && safe_fd(fd,false,true) && !fstat(fd,&staged);
 if(close(fd))ok=false;
 fd=-1;
 // Compare both full raw objects and their descriptor identity immediately
 // before publishing. External replacement never becomes a successful CAS.
 if(ok){
  size_t size=0;bool absent;struct stat actual;
  char *written=read_file(dir,TEMP,LIMIT,&size,&absent,&actual);
  ok=written && size==ucv_string_length(v) && !memcmp(written,ucv_string_get(v),size) &&
   same_stat(&staged,&actual) && matching(dir,expected);
  free(written);
 }
 if(ok)ok=!renameat(dir,TEMP,dir,STATE) && directory_current(dir);
 done:
 if(fd>=0)close(fd);
 if(dir>=0 && close(dir))ok=false;
 return ok ? ucv_boolean_new(true) : storage_error(vm);
}

static char *start_ticks(pid_t pid, bool *missing)
{
	char path[64], data[2048];
	char *p, *end, *result = NULL;
	unsigned retries = 0;
	ssize_t n;
	int fd;
	snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	*missing = fd < 0 && errno == ENOENT;
	if (fd < 0) return NULL;
	do { n = read(fd, data, sizeof(data) - 1); } while (n < 0 && errno == EINTR && retries++ < RETRIES);
	if (close(fd) || n <= 0 || n >= (ssize_t)sizeof(data) - 1) return NULL;
	data[n] = 0; p = strrchr(data, ')');
	if (!p || p[1] != ' ') return NULL;
	p += 2;
	if (*p == 'Z' || *p == 'X') { *missing = true; return NULL; }
	for (unsigned field = 3; field <= 22; field++) {
		end = strchr(p, ' ');
		if (!end) return NULL;
		if (field == 22) {
			if (end == p || end - p > 20) return NULL;
			for (char *q = p; q < end; q++) if (*q < '0' || *q > '9') return NULL;
			result = strndup(p, (size_t)(end - p)); break;
		}
		p = end + 1;
	}
	return result;
}

static uc_value_t *owner(uc_vm_t *vm, size_t nargs)
{
	bool missing;
	char *ticks = start_ticks(getpid(), &missing);
	uc_value_t *result;
	if (nargs || !ticks) { free(ticks); return storage_error(vm); }
	result = ucv_object_new(vm);
	ucv_object_add(result, "pid", ucv_int64_new(getpid()));
	ucv_object_add(result, "start_ticks", ucv_string_new(ticks)); free(ticks);
	return result;
}

static uc_value_t *alive(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *p = uc_fn_arg(0), *s = uc_fn_arg(1);
	bool missing;
	char *ticks;
	if (nargs != 2 || ucv_type(p) != UC_INTEGER || ucv_int64_get(p) < 1 ||
	    ucv_int64_get(p) > 2147483647 || ucv_type(s) != UC_STRING ||
	    !ucv_string_length(s) || ucv_string_length(s) > 20) return storage_error(vm);
	ticks = start_ticks((pid_t)ucv_int64_get(p), &missing);
	if (!ticks) return missing ? ucv_boolean_new(false) : storage_error(vm);
	bool result = strlen(ticks) == ucv_string_length(s) && !memcmp(ticks, ucv_string_get(s), strlen(ticks));
	free(ticks); return ucv_boolean_new(result);
}

static uc_value_t *monotonic(uc_vm_t *vm, size_t nargs)
{
	struct timespec t;
	if (nargs || clock_gettime(CLOCK_MONOTONIC, &t) || t.tv_sec < 0) return storage_error(vm);
	return ucv_int64_new((int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000);
}

static const uc_function_list_t functions[] = {
	{ "read", read_runtime }, { "publish", publish }, { "owner", owner },
	{ "alive", alive }, { "now", monotonic }
};
void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	(void)vm;
	uc_function_list_register(scope, functions);
}
