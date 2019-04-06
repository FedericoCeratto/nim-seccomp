#
# Test application: trigger seccomp to terminate the process
#
# 2016 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv2.1, see LICENSE file
#

import os, net

import seccomp

if paramCount() < 1:
  # When run without any parameter, act as a wrapper for the tests
  const test_names = @["mkdir", "mkdir_helper", "rmdir",
  "walkdir", "nothing", "open", "stat", "sleep", "update_seccomp",
  "socket", "sendto", "bind", "listen", "connect", "execShellCmd"]
  var failed_tests_cnt = 0
  for tname in test_names:
    let a = execShellCmd("./tests/trigger_seccomp " & tname)
    case a:
      of 159:
        echo "OK"
      of 0:
        if tname == "nothing" or tname == "execShellCmd":
          echo "OK"
        else:
          echo "Unexpected success"
          failed_tests_cnt.inc
      else:
        echo "Unexpected " & $a
        failed_tests_cnt.inc

  echo $failed_tests_cnt & " failed tests"
  quit(-1 * failed_tests_cnt)

echo ""
echo "Testing ", paramStr(1)

template setup() =
  let ctx = seccomp_ctx()
  # Required to print progress
  ctx.add_rule(Allow, "write")
  # Required to let failed tests exit without triggering seccomp
  ctx.add_rule(Allow, "exit_group")
  ctx.load()

case paramStr(1)
of "mkdir":
  setup
  createDir("/tmp/seccomp_test")
of "mkdir_helper":
  setSeccomp("write exit_group")
  createDir("/tmp/seccomp_test")
of "rmdir":
  setup
  removeDir("/tmp/seccomp_test")
of "walkdir":
  setup
  for kind, path in walkDir("/tmp"):
    echo(path)
of "nothing":
  setup
of "open":
  setup
  discard open("/dev/zero", fmRead)
of "stat":
  setup
  discard getFilePermissions("/tmp/foo")
of "sleep":
  setup
  sleep(1)
of "update_seccomp":
  setup
  # Try to load a new seccomp ctx
  let ctx = seccomp_ctx()
  ctx.add_rule(Allow, "write")
  ctx.add_rule(Allow, "exit_group")
  ctx.load()
of "socket":
  setup
  discard newSocket()
of "sendto":
  setup
  var s = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
  s.sendTo("127.0.0.1", Port(12345), "hi")
of "bind":
  var s = newSocket()
  setup
  s.bindAddr(Port(12345))
of "listen":
  var s = newSocket()
  s.bindAddr(Port(12345))
  setup
  s.listen()
of "connect":
  var s = newSocket()
  setup
  s.connect("localhost", Port(80))
of "execShellCmd":
  setSeccomp("read write execve shmctl rt_sigaction rt_sigprocmask clone brk access openat fstat close mmap mprotect arch_prctl munmap getuid getgid getpid geteuid getppid stat getegid set_tid_address set_robust_list prlimit64 lseek alarm fcntl wait4 rt_sigreturn exit_group prctl statfs")
  doAssert execShellCmd("true") == 0
else:
  echo "Unknown test name"
