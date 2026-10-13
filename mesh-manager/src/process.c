// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <libubox/uloop.h>
#include <ucode/module.h>

#define LIMIT 65536
#define INPUT_LIMIT (1024 * 1024)
#define ARGS 48
#define FD_ENTRIES 4096
#define ASYNC_LIMIT (1024 * 1024)
#define ASYNC_JOBS 2

static volatile sig_atomic_t command_group;

static int close_inherited(void)
{
#ifdef SYS_close_range
	if (syscall(SYS_close_range, 3U, UINT_MAX, 0U) == 0) return 0;
#endif
	DIR *directory = opendir("/proc/self/fd");
	if (!directory) return -1;
	int keep = dirfd(directory), result = -1;
	for (unsigned int count = 0; count < FD_ENTRIES; count++) {
		errno = 0;
		struct dirent *entry = readdir(directory);
		if (!entry) { result = errno ? -1 : 0; break; }
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
		char *end;
		errno = 0;
		long fd = strtol(entry->d_name, &end, 10);
		if (errno || *end || fd < 0 || fd > INT_MAX) break;
		if (fd <= STDERR_FILENO || fd == keep) continue;
		if (close((int)fd) && errno != EBADF && errno != EINTR) break;
	}
	if (closedir(directory)) result = -1;
	/* A lowered descriptor limit cannot prove that previously opened high FDs are absent. */
	return result;
}

static void cancel_group(int signal_number)
{
	(void)signal_number;
	if (command_group > 0) kill(-(pid_t)command_group, SIGKILL);
	kill(getpid(), SIGKILL);
	_exit(127);
}

static void supervise(char **args, FILE *in, FILE *out, pid_t parent, pid_t parent_group, int timeout)
{
	struct sigaction action = { .sa_handler = cancel_group };
	struct rlimit limit = { INPUT_LIMIT + 1, INPUT_LIMIT + 1 };
	struct itimerval deadline = { .it_value = { timeout / 1000, (timeout % 1000) * 1000 } };
	sigset_t unblocked;
	pid_t command;
	int status, err;

	command_group = getpid();
	sigemptyset(&action.sa_mask);
	sigemptyset(&unblocked);
	sigaddset(&unblocked, SIGTERM);
	sigaddset(&unblocked, SIGALRM);
	if (setpgid(0, 0) || sigaction(SIGTERM, &action, NULL) ||
	    sigaction(SIGALRM, &action, NULL) || setitimer(ITIMER_REAL, &deadline, NULL) ||
	    sigprocmask(SIG_UNBLOCK, &unblocked, NULL) ||
	    prctl(PR_SET_PDEATHSIG, SIGTERM) || getppid() != parent)
		cancel_group(SIGTERM);
	err = open("/dev/null", O_WRONLY | O_CLOEXEC);
	if (err < 0 || setrlimit(RLIMIT_FSIZE, &limit) ||
	    dup2(fileno(in), STDIN_FILENO) < 0 || dup2(fileno(out), STDOUT_FILENO) < 0 ||
	    dup2(err, STDERR_FILENO) < 0)
		_exit(127);
	/* The supervisor and command must not retain journal locks or authenticated sockets. */
	if (close_inherited()) _exit(127);
	command = fork();
	if (!command) {
		if (signal(SIGTERM, SIG_DFL) == SIG_ERR || signal(SIGALRM, SIG_DFL) == SIG_ERR ||
		    prctl(PR_SET_PDEATHSIG, SIGKILL) ||
		    getppid() != (pid_t)command_group)
			_exit(127);
		execv(args[0], args);
		_exit(127);
	}
	if (command < 0) _exit(127);
	while (waitpid(command, &status, 0) < 0) {
		if (errno != EINTR) cancel_group(SIGTERM);
	}
	/* Leave our group before cancelling background descendants, preserving the command's exit code. */
	if (setpgid(0, parent_group)) cancel_group(SIGTERM);
	kill(-(pid_t)command_group, SIGKILL);
	if (WIFEXITED(status)) _exit(WEXITSTATUS(status));
	kill(getpid(), SIGKILL);
	_exit(127);
}

static uc_value_t *run(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *list = uc_fn_arg(0), *input = uc_fn_arg(1), *timeout = uc_fn_arg(2);
	char *args[ARGS + 1] = { 0 };
	FILE *in = NULL, *out = NULL;
	pid_t child = -1, parent = getpid(), parent_group = getpgrp();
	int status = 0, code = -1;
	uc_value_t *result = NULL;
	if (ucv_type(list) != UC_ARRAY || !ucv_array_length(list) || ucv_array_length(list) > ARGS ||
	    ucv_type(input) != UC_STRING || ucv_string_length(input) > INPUT_LIMIT ||
	    ucv_type(timeout) != UC_INTEGER || ucv_int64_get(timeout) < 1 || ucv_int64_get(timeout) > 30000)
		return NULL;
	for (size_t i = 0; i < ucv_array_length(list); i++) {
		uc_value_t *v = ucv_array_get(list, i);
		if (ucv_type(v) != UC_STRING || ucv_string_length(v) > 4096 ||
		    memchr(ucv_string_get(v), 0, ucv_string_length(v))) goto done;
		args[i] = strdup(ucv_string_get(v));
		if (!args[i]) goto done;
	}
	if (args[0][0] != '/' || !(in = tmpfile()) || !(out = tmpfile())) goto done;
	if (fwrite(ucv_string_get(input), 1, ucv_string_length(input), in) != ucv_string_length(input) ||
	    fflush(in) || fseek(in, 0, SEEK_SET)) goto done;
	struct timespec start, now, pause = { 0, 10000000 };
	if (clock_gettime(CLOCK_MONOTONIC, &start)) goto done;
	child = fork();
	if (child == 0) supervise(args, in, out, parent, parent_group, (int)ucv_int64_get(timeout));
	if (child < 0) goto done;
	for (;;) {
		pid_t waited = waitpid(child, &status, WNOHANG);
		if (waited == child) {
			code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
			clock_gettime(CLOCK_MONOTONIC, &now);
			if ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000 >= ucv_int64_get(timeout))
				code = -2;
			break;
		}
		if (waited < 0 && errno != EINTR) break;
		clock_gettime(CLOCK_MONOTONIC, &now);
		if ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000 >= ucv_int64_get(timeout)) {
			kill(-child, SIGKILL);
			/* Cover cancellation before the supervisor has created its process group. */
			kill(child, SIGTERM);
			while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
			code = -2;
			break;
		}
		nanosleep(&pause, NULL);
	}
	struct stat st;
	if (fstat(fileno(out), &st) || st.st_size > LIMIT || fseek(out, 0, SEEK_SET)) goto done;
	char *buffer = malloc((size_t)st.st_size + 1);
	if (!buffer) goto done;
	size_t size = fread(buffer, 1, (size_t)st.st_size, out);
	result = ucv_object_new(vm);
	ucv_object_add(result, "code", ucv_int64_new(code));
	ucv_object_add(result, "stdout", ucv_string_new_length(buffer, size));
	free(buffer);
done:
	if (in) fclose(in);
	if (out) fclose(out);
	for (size_t i = 0; i < ARGS; i++) free(args[i]);
	return result;
}

struct async_job {
	uc_vm_t *vm;
	uc_value_t *object;
	struct uloop_process process;
	struct uloop_timeout timer;
	FILE *output;
	struct timespec started;
	int timeout;
	int cancelled;
	bool running;
};

static unsigned int active_jobs;

static bool expired(const struct async_job *job)
{
	struct timespec clock;
	return clock_gettime(CLOCK_MONOTONIC, &clock) ||
	       (clock.tv_sec - job->started.tv_sec) * 1000 +
	       (clock.tv_nsec - job->started.tv_nsec) / 1000000 >= job->timeout;
}

static void async_cancel(struct async_job *job, int reason)
{
	if (!job->running || job->cancelled) return;
	job->cancelled = reason;
	uloop_timeout_cancel(&job->timer);
	/* The supervisor also enforces its own deadline if the event loop is stalled. */
	kill(-job->process.pid, SIGKILL);
	kill(job->process.pid, SIGKILL);
}

static void async_timeout(struct uloop_timeout *timer)
{
	struct async_job *job = container_of(timer, struct async_job, timer);
	async_cancel(job, -2);
}

static uc_value_t *async_result(struct async_job *job, int status)
{
	int code = job->cancelled ? job->cancelled : expired(job) ? -2 :
	           WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	struct stat st;
	char *buffer = NULL;
	size_t length = 0;
	if (fstat(fileno(job->output), &st) || st.st_size < 0 || st.st_size > ASYNC_LIMIT ||
	    fseek(job->output, 0, SEEK_SET)) {
		code = -4;
	} else if (st.st_size) {
		buffer = malloc((size_t)st.st_size);
		if (!buffer || (length = fread(buffer, 1, (size_t)st.st_size, job->output)) != (size_t)st.st_size) {
			code = -4;
			length = 0;
		}
	}
	uc_value_t *result = ucv_object_new(job->vm);
	ucv_object_add(result, "code", ucv_int64_new(code));
	ucv_object_add(result, "stdout", ucv_string_new_length(buffer ? buffer : "", length));
	free(buffer);
	return result;
}

static void async_finished(struct uloop_process *process, int status)
{
	struct async_job *job = container_of(process, struct async_job, process);
	uc_value_t *object = job->object, *callback = ucv_resource_value_get(object, 0);
	uc_value_t *result = async_result(job, status);
	job->running = false;
	active_jobs--;
	uloop_timeout_cancel(&job->timer);
	fclose(job->output);
	job->output = NULL;
	/* Finish native ownership before invoking a callback which may start another job. */
	ucv_get(callback);
	ucv_resource_value_set(object, 0, NULL);
	if (ucv_is_callable(callback)) {
		uc_vm_stack_push(job->vm, callback);
		uc_vm_stack_push(job->vm, result);
		if (uc_vm_call(job->vm, false, 1) == EXCEPTION_NONE) {
			ucv_put(uc_vm_stack_pop(job->vm));
		} else {
			uc_value_t *handler = uc_vm_registry_get(job->vm, "uloop.ex_handler");
			if (ucv_is_callable(handler)) {
				uc_vm_stack_push(job->vm, ucv_get(handler));
				uc_vm_stack_push(job->vm, uc_vm_exception_object(job->vm));
				if (uc_vm_call(job->vm, false, 1) == EXCEPTION_NONE)
					ucv_put(uc_vm_stack_pop(job->vm));
				else uloop_end();
			} else uloop_end();
		}
	} else {
		ucv_put(callback);
		ucv_put(result);
	}
	job->object = NULL;
	ucv_resource_persistent_set(object, false);
	ucv_put(object);
}

static void async_free(void *data)
{
	struct async_job *job = data;
	if (job->running) {
		async_cancel(job, -3);
		uloop_process_delete(&job->process);
		while (waitpid(job->process.pid, NULL, 0) < 0 && errno == EINTR) {}
		active_jobs--;
	}
	if (job->output) fclose(job->output);
	job->object = NULL;
}

static uc_value_t *job_cancel(uc_vm_t *vm, size_t nargs)
{
	struct async_job *job = uc_fn_thisval("mesh_process.job");
	(void)nargs;
	if (!job) return NULL;
	async_cancel(job, -3);
	return ucv_boolean_new(true);
}

static uc_value_t *job_running(uc_vm_t *vm, size_t nargs)
{
	struct async_job *job = uc_fn_thisval("mesh_process.job");
	(void)nargs;
	return job ? ucv_boolean_new(job->running) : NULL;
}

static uc_value_t *start(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *list = uc_fn_arg(0), *input = uc_fn_arg(1), *timeout = uc_fn_arg(2),
	           *callback = uc_fn_arg(3), *object = NULL;
	char *args[ARGS + 1] = { 0 };
	struct async_job *job;
	FILE *in = NULL, *out = NULL;
	pid_t child = -1, parent = getpid(), parent_group = getpgrp();
	int duration;
	if (nargs != 4 || active_jobs >= ASYNC_JOBS || ucv_type(list) != UC_ARRAY ||
	    !ucv_array_length(list) || ucv_array_length(list) > ARGS ||
	    ucv_type(input) != UC_STRING || ucv_string_length(input) > INPUT_LIMIT ||
	    ucv_type(timeout) != UC_INTEGER || ucv_int64_get(timeout) < 1 ||
	    ucv_int64_get(timeout) > 30000 || !ucv_is_callable(callback))
		return NULL;
	duration = (int)ucv_int64_get(timeout);
	for (size_t i = 0; i < ucv_array_length(list); i++) {
		uc_value_t *value = ucv_array_get(list, i);
		if (ucv_type(value) != UC_STRING || ucv_string_length(value) > 4096 ||
		    memchr(ucv_string_get(value), 0, ucv_string_length(value))) goto done;
		args[i] = strdup(ucv_string_get(value));
		if (!args[i]) goto done;
	}
	if (args[0][0] != '/' || !(in = tmpfile()) || !(out = tmpfile()) ||
	    fwrite(ucv_string_get(input), 1, ucv_string_length(input), in) != ucv_string_length(input) ||
	    fflush(in) || fseek(in, 0, SEEK_SET) || uloop_init()) goto done;
	object = ucv_resource_create_ex(vm, "mesh_process.job", (void **)&job, 1, sizeof(*job));
	if (!object) goto done;
	job->vm = vm;
	job->object = object;
	job->timeout = duration;
	job->process.cb = async_finished;
	job->timer.cb = async_timeout;
	if (clock_gettime(CLOCK_MONOTONIC, &job->started)) goto failed;
	child = fork();
	if (child == 0) supervise(args, in, out, parent, parent_group, duration);
	if (child < 0) goto failed;
	job->process.pid = child;
	if (uloop_process_add(&job->process)) {
		kill(-child, SIGKILL);
		kill(child, SIGKILL);
		while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
		goto failed;
	}
	job->running = true;
	job->output = out;
	out = NULL;
	active_jobs++;
	if (uloop_timeout_set(&job->timer, duration)) goto failed;
	ucv_resource_value_set(object, 0, ucv_get(callback));
	ucv_resource_persistent_set(object, true);
	ucv_get(object);
	goto done;
failed:
	ucv_put(object);
	object = NULL;
done:
	if (in) fclose(in);
	if (out) fclose(out);
	for (size_t i = 0; i < ARGS; i++) free(args[i]);
	return object;
}

static const uc_function_list_t job_functions[] = {
	{ "cancel", job_cancel }, { "running", job_running }
};
static const uc_function_list_t functions[] = { { "run", run }, { "start", start } };
void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_type_declare(vm, "mesh_process.job", job_functions, async_free);
	uc_function_list_register(scope, functions);
}
