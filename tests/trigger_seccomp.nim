#
# Test application: trigger seccomp to terminate the process
#
# 2016 Federico Ceratto <federico.ceratto@gmail.com>
# Released under LGPLv2.1, see LICENSE file
#

import os, net

import seccomp

if paramCount() < 1:
  echo "Missing parameter"
  quit(1)

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
  echo "This test is expected to fail with 'FAILED' in the next line and no 'OK'"
  discard
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
else:
  echo "Unknown test name"

echo "FAILED"
