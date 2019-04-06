# Package

version       = "0.1.0"
author        = "Federico Ceratto"
description   = "Seccomp (Linux sandboxing) adapter"
license       = "LGPLv2.1"

# Dependencies

requires "nim >= 0.13.0"

task release, "Build a release":
  exec "nim c -d:release seccomp.nim"

task test, "Basic test":
  exec "nim c -p:. -r tests/basic_test.nim"
  exec "nim c -p:. -r tests/syscall_num.nim"

task test_trigger_seccomp, "Test triggering seccomp":
  exec "nim c -p:. tests/trigger_seccomp.nim"
  let tests = @["mkdir", "mkdir_helper", "rmdir",
  "walkdir", "nothing", "open", "stat", "sleep", "update_seccomp",
  "socket", "sendto", "bind", "listen", "connect"]
  for tname in tests:
    exec("./tests/trigger_seccomp " & tname & " || echo OK")
    #exec("strace ./tests/trigger_seccomp " & tname & " || echo OK")
