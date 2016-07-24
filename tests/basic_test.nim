
import os, unittest

import seccomp

suite "seccomp":

  test "version":
    echo "version ",  get_version()
    doAssert get_version()[0] == 2

  test "reset":
    let ctx1 = seccomp_ctx()
    ctx1.reset()

  test "real ctx":
    let ctx = seccomp_ctx()
    ctx.add_rule(Allow, "read")
    ctx.add_rule(Allow, "write")
    ctx.add_rule(Allow, "exit_group")
    ctx.load()

  test "reset":
    let ctx = seccomp_ctx()
    ctx.reset()

  test "release":
    let ctx = seccomp_ctx()
    ctx.release()
