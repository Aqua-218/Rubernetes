#include <ruby.h>

#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

extern char **environ;

enum failure_stage {
  FAILURE_PARENT_DEATH_SIGNAL = 1,
  FAILURE_PRIVATE_MOUNT = 2,
  FAILURE_PROC_MOUNT = 3,
  FAILURE_DUP_OUTPUT = 4,
  FAILURE_EXEC = 5
};

struct child_failure {
  int stage;
  int error_number;
};

static const uint64_t REQUIRED_CLONE_FLAGS = CLONE_PIDFD | CLONE_NEWNS | CLONE_NEWPID;
static const long MAX_ARGUMENT_COUNT = 4096;

static void
child_fail(int descriptor, int stage, int error_number)
{
  struct child_failure failure = {stage, error_number};
  ssize_t ignored = write(descriptor, &failure, sizeof(failure));
  (void)ignored;
  _exit(127);
}

static VALUE
linux_clone3_exec(VALUE self, VALUE flags_value, VALUE arguments_value,
                  VALUE proc_target_value, VALUE output_fd_value)
{
  (void)self;
  Check_Type(arguments_value, T_ARRAY);
  long argument_count = RARRAY_LEN(arguments_value);
  if (argument_count < 1 || argument_count > MAX_ARGUMENT_COUNT) {
    rb_raise(rb_eArgError, "arguments must contain between 1 and 4096 entries");
  }

  char **arguments = ALLOCA_N(char *, (size_t)argument_count + 1);
  for (long index = 0; index < argument_count; index++) {
    VALUE argument = rb_ary_entry(arguments_value, index);
    arguments[index] = StringValueCStr(argument);
  }
  arguments[argument_count] = NULL;
  if (arguments[0][0] != '/') {
    rb_raise(rb_eArgError, "executable path must be absolute");
  }

  const char *proc_target = StringValueCStr(proc_target_value);
  int output_fd = NUM2INT(output_fd_value);
  uint64_t clone_flags = NUM2ULL(flags_value);
  if (clone_flags != REQUIRED_CLONE_FLAGS) {
    rb_raise(rb_eArgError, "flags must be exactly CLONE_PIDFD | CLONE_NEWNS | CLONE_NEWPID");
  }
  int error_pipe[2];
  if (pipe2(error_pipe, O_CLOEXEC) == -1) {
    int saved_errno = errno;
    rb_syserr_fail(saved_errno, "pipe2");
  }

  int pidfd = -1;
  struct clone_args clone_arguments = {0};
  clone_arguments.flags = clone_flags;
  clone_arguments.pidfd = (uintptr_t)&pidfd;
  clone_arguments.exit_signal = SIGCHLD;

  pid_t pid = (pid_t)syscall(SYS_clone3, &clone_arguments, sizeof(clone_arguments));
  if (pid == -1) {
    int saved_errno = errno;
    close(error_pipe[0]);
    close(error_pipe[1]);
    rb_syserr_fail(saved_errno, "clone3");
  }

  if (pid == 0) {
    close(error_pipe[0]);
    if (syscall(SYS_prctl, PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == -1) {
      child_fail(error_pipe[1], FAILURE_PARENT_DEATH_SIGNAL, errno);
    }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
      child_fail(error_pipe[1], FAILURE_PRIVATE_MOUNT, errno);
    }
    if (mount("proc", proc_target, "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == -1) {
      child_fail(error_pipe[1], FAILURE_PROC_MOUNT, errno);
    }
    if (output_fd >= 0) {
      if (dup2(output_fd, STDOUT_FILENO) == -1 || dup2(output_fd, STDERR_FILENO) == -1) {
        child_fail(error_pipe[1], FAILURE_DUP_OUTPUT, errno);
      }
      if (output_fd != STDOUT_FILENO && output_fd != STDERR_FILENO) {
        close(output_fd);
      }
    }
    execve(arguments[0], arguments, environ);
    child_fail(error_pipe[1], FAILURE_EXEC, errno);
  }

  close(error_pipe[1]);
  VALUE result = rb_ary_new_capa(3);
  rb_ary_push(result, PIDT2NUM(pid));
  rb_ary_push(result, INT2NUM(pidfd));
  rb_ary_push(result, INT2NUM(error_pipe[0]));
  return result;
}

void
Init_rubernetes_linux(void)
{
  VALUE rubernetes = rb_define_module("Rubernetes");
  VALUE linux_native = rb_define_module_under(rubernetes, "LinuxNative");
  rb_define_singleton_method(linux_native, "clone3_exec", linux_clone3_exec, 4);
}
