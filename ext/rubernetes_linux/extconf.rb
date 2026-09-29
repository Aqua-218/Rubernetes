# frozen_string_literal: true

require "mkmf"

abort "Linux is required" unless RUBY_PLATFORM.include?("linux")
abort "linux/sched.h with clone3 is required" unless have_header("linux/sched.h")
abort "SYS_clone3 is required" unless have_const("SYS_clone3", "sys/syscall.h")

$CFLAGS = "#{$CFLAGS} -std=c11 -Wall -Wextra -Werror"
create_makefile("rubernetes_linux")
